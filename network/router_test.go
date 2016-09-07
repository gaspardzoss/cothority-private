package network

import (
	"sync"
	"testing"
	"time"

	"github.com/dedis/cothority/log"
	"github.com/stretchr/testify/assert"
)

func NewTestRouterTCP(port int) (*Router, error) {
	h, err := NewTestTCPHost(port)
	if err != nil {
		return nil, err
	}
	id := NewTestServerIdentity(h.addr)
	return NewRouter(id, h), nil
}

func NewTestRouterLocal(port int) (*Router, error) {
	h, err := NewTestLocalHost(port)
	if err != nil {
		return nil, err
	}
	id := NewTestServerIdentity(h.addr)
	return NewRouter(id, h), nil
}

type routerFactory func(port int) (*Router, error)

// Test if router fits the interface such as calling Run(), then Stop(),
// should return
func TestRouterTCP(t *testing.T) {
	testRouter(t, NewTestRouterTCP)
}
func TestRouterLocal(t *testing.T) {
	testRouter(t, NewTestRouterLocal)
}

func testRouter(t *testing.T, fac routerFactory) {
	h, err := fac(2004)
	if err != nil {
		t.Fatal(err)
	}
	var stop = make(chan bool)
	go func() {
		stop <- true
		h.Start()
		stop <- true
	}()
	<-stop
	// Time needed so the listener is up. Equivalent to "connecting ourself" as
	// we had before.
	time.Sleep(250 * time.Millisecond)
	h.Stop()
	select {
	case <-stop:
		return
	case <-time.After(500 * time.Millisecond):
		t.Fatal("TcpHost should have returned from Run() by now")
	}
}

// Test the automatic connection upon request
func TestRouterAutoConnectionTCP(t *testing.T) {
	testRouterAutoConnection(t, NewTestRouterTCP)
}
func TestRouterAutoConnectionLocal(t *testing.T) {
	testRouterAutoConnection(t, NewTestRouterLocal)
}

func testRouterAutoConnection(t *testing.T, fac routerFactory) {
	h1, err := fac(2007)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := fac(2008)
	if err != nil {
		t.Fatal(err)
	}
	go h2.Start()

	proc := newSimpleMessageProc(t)
	h2.RegisterProcessor(proc, SimpleMessageType)
	h1.RegisterProcessor(proc, SimpleMessageType)
	defer func() {
		assert.Nil(t, h1.Stop())
		assert.Nil(t, h2.Stop())
	}()

	err = h1.Send(h2.id, &SimpleMessage{12})
	if err != nil {
		t.Fatal("Couldn't send message:", err)
	}

	// Receive the message
	msg := <-proc.relay
	if msg.I != 12 {
		t.Fatal("Simple message got distorted")
	}

	h12 := h1.connection(h2.id.ID)
	h21 := h2.connection(h1.id.ID)
	if h12 == nil {
		t.Error("h1 has no connection to h2")
	} else if h21 == nil {
		t.Error("h2 has no connection to h1")
	}
}

// Test connection of multiple Hosts and sending messages back and forth
// also tests for the counterIO interface that it works well
func TestRouterMessaging(t *testing.T) {
	h1, err1 := NewTestRouterTCP(2009)
	h2, err2 := NewTestRouterTCP(2010)
	if err1 != nil || err2 != nil {
		t.Fatal("Could not setup hosts")
	}

	go h1.Start()
	go h2.Start()

	defer func() {
		h1.Stop()
		h2.Stop()
		time.Sleep(250 * time.Millisecond)
	}()

	proc := &simpleMessageProc{t, make(chan SimpleMessage)}
	h1.RegisterProcessor(proc, SimpleMessageType)
	h2.RegisterProcessor(proc, SimpleMessageType)

	msgSimple := &SimpleMessage{3}
	err := h1.Send(h2.id, msgSimple)
	if err != nil {
		t.Fatal("Couldn't send from h2 -> h1:", err)
	}
	decoded := <-proc.relay
	if decoded.I != 3 {
		t.Fatal("Received message from h2 -> h1 is wrong")
	}

	// make sure the connection is registered in host1 (because it's launched in
	// a go routine). Since we try to avoid random timeout, let's send a msg
	// from host2 -> host1.
	assert.Nil(t, h2.Send(h1.id, msgSimple))
	decoded = <-proc.relay
	assert.Equal(t, 3, decoded.I)

	written := h1.Tx()
	read := h2.Rx()
	if written == 0 || read == 0 || written != read {
		t.Logf("Tx = %d, Rx = %d", written, read)
		t.Logf("h1.Tx() %d vs h2.Rx() %d", h1.Tx(), h2.Rx())
		t.Fatal("Something is wrong with Host.CounterIO")
	}
}

func TestRouterLotsOfConnTCP(t *testing.T) {
	testRouterLotsOfConn(t, NewTestRouterTCP)
}

func TestRouterLotsOfConnLocal(t *testing.T) {
	testRouterLotsOfConn(t, NewTestRouterLocal)
}

// nSquareProc will send back all packet sent and stop when it has received
// enough, it releases the waitgroup.
type nSquareProc struct {
	t        *testing.T
	r        *Router
	expected int
	actual   int
	wg       *sync.WaitGroup
	sync.Mutex
}

func newNSquareProc(t *testing.T, r *Router, expect int, wg *sync.WaitGroup) *nSquareProc {
	return &nSquareProc{t, r, expect, 0, wg, sync.Mutex{}}
}

func (p *nSquareProc) Process(pack *Packet) {
	p.Lock()
	defer p.Unlock()
	p.actual++
	log.Print(p.r.id, p.actual, p.expected)
	if p.actual == p.expected {
		// release
		log.Print(p.r.id, "done")
		p.wg.Done()
		return
	} else if p.actual > p.expected {
		log.Fatal("Too many responses")
	}
	msg := pack.Msg.(SimpleMessage)
	// Only send message back if it's the first one.
	log.Print(p.r.id, msg.I)
	if msg.I == 0 {
		log.Print(p.r.id, "sending to", pack.ServerIdentity)
		p.r.Send(pack.ServerIdentity, &SimpleMessage{1})
	}
}

// Makes a big mesh where every host send and receive to every other hosts
func testRouterLotsOfConn(t *testing.T, fac routerFactory) {
	nbrRouter := 3
	// create all the routers
	routers := make([]*Router, nbrRouter)
	var wg1 sync.WaitGroup
	wg1.Add(nbrRouter)
	for i := 0; i < nbrRouter; i++ {
		go func(j int) {
			r, err := fac(2000 + j)
			if err != nil {
				t.Fatal(err)
			}
			go r.Start()
			for !r.Listening() {
				log.Lvl2("Waiting for listening")
				time.Sleep(20 * time.Millisecond)
			}
			routers[j] = r
			wg1.Done()
		}(i)
	}
	wg1.Wait()
	log.Lvl1("Done adding routers")

	var wg2 sync.WaitGroup
	wg2.Add(nbrRouter)
	for i := 0; i < nbrRouter; i++ {
		go func(j int) {
			r := routers[j]
			// expect nbrRouter - 1 messages
			proc := newNSquareProc(t, r, (nbrRouter-1)*2, &wg2)
			r.RegisterProcessor(proc, SimpleMessageType)
			for k := 0; k < nbrRouter; k++ {
				if k == j {
					// don't send to yourself
					continue
				}
				// send to everyone else
				log.Print("Sending", r.id, routers[k].id)
				if err := r.Send(routers[k].id, &SimpleMessage{0}); err != nil {
					t.Fatal(err)
				}
			}
		}(i)
		time.Sleep(time.Second)
	}
	wg2.Wait()
	log.Lvl1("Finished sending messages")
	time.Sleep(time.Second)

	for i := 0; i < nbrRouter; i++ {
		r := routers[i]
		log.Lvl1("Stopping router", i)
		if err := r.Stop(); err != nil {
			log.Print("Fataling out")
			t.Fatal(err)
		}
		log.Print("Router", i, "stopped")

	}
	log.Lvl1("Closed all routers")
}

// Test sending data back and forth using the sendSDAData
func TestRouterSendMsgDuplexTCP(t *testing.T) {
	testRouterSendMsgDuplex(t, NewTestRouterTCP)
}

func TestRouterSendMsgDuplexLocal(t *testing.T) {
	testRouterSendMsgDuplex(t, NewTestRouterLocal)
}
func testRouterSendMsgDuplex(t *testing.T, fac routerFactory) {
	h1, err1 := fac(2011)
	h2, err2 := fac(2012)
	if err1 != nil || err2 != nil {
		t.Fatal("Could not setup hosts")
	}
	go h1.Start()
	go h2.Start()

	defer func() {
		h1.Stop()
		h2.Stop()
		time.Sleep(250 * time.Millisecond)
	}()

	proc := &simpleMessageProc{t, make(chan SimpleMessage)}
	h1.RegisterProcessor(proc, SimpleMessageType)
	h2.RegisterProcessor(proc, SimpleMessageType)

	msgSimple := &SimpleMessage{5}
	err := h1.Send(h2.id, msgSimple)
	if err != nil {
		t.Fatal("Couldn't send message from h1 to h2", err)
	}
	msg := <-proc.relay
	log.Lvl2("Received msg h1 -> h2", msg)

	err = h2.Send(h1.id, msgSimple)
	if err != nil {
		t.Fatal("Couldn't send message from h2 to h1", err)
	}
	msg = <-proc.relay
	log.Lvl2("Received msg h2 -> h1", msg)
}

func TestRouterExchange(t *testing.T) {
	router1, err := NewTestRouterTCP(7878)
	router2, err2 := NewTestRouterTCP(8787)
	if err != nil || err2 != nil {
		t.Fatal("Could not setup host", err, err2)
	}

	done := make(chan bool)
	go func() {
		done <- true
		router1.Start()
		done <- true
	}()
	<-done
	// try correctly
	c, err := NewTCPConn(router1.id.Address)
	if err != nil {
		t.Fatal("Couldn't connect to host1:", err)
	}
	if err := router2.negotiateOpen(router1.id, c); err != nil {
		t.Fatal("Wrong negotiation")
	}
	c.Close()

	// try giving wrong id
	c, err = NewTCPConn(router1.id.Address)
	if err != nil {
		t.Fatal("Couldn't connect to host1:", err)
	}
	if err := router2.negotiateOpen(router2.id, c); err == nil {
		t.Fatal("negotiation should have aborted")
	}
	c.Close()

	log.Lvl4("Closing connections")
	if err := router2.Stop(); err != nil {
		t.Fatal("Couldn't close host", err)
	}
	if err := router1.Stop(); err != nil {
		t.Fatal("Couldn't close host", err)
	}
	<-done
}
