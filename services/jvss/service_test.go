package jvss_service

import (
	"testing"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/network"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func NewTestClient(lt *sda.LocalTest) *Client {
	return &Client{Client: lt.NewClient(ServiceName)}
}

func TestJVSSService(t *testing.T) {
	log.TestOutput(true, 2)
	msg := []byte("Hello world")
	local := sda.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, false)
	defer local.CloseAll()

	// Send a request to the service
	client := NewTestClient(local)

	log.Lvl1("Sending setup request to service...")
	pub, err := client.Setup(el)
	log.ErrFatal(err, "Couldn't send")
	log.Lvl1("Sending sign request to service...")
	sig, err := client.Sign(el, msg)
	log.ErrFatal(sig.Verify(network.Suite, *pub, msg))
}
