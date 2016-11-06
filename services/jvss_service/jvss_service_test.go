package jvss_service

import (
	"testing"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/sda"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func NewTestClient(lt *sda.LocalTest) *Client {
	return &Client{Client: lt.NewClient(ServiceName)}
}

func TestJVSSService(t *testing.T) {
	log.SetDebugVisible(2)
	msg := []byte("Hello world")
	local := sda.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := NewTestClient(local)
	log.Lvl1("Sending request to service...")
	err := client.Setup(el)
	log.ErrFatal(err, "Couldn't send")
	sig, err := client.Sign(el,msg)
	if sig != nil {
		log.Lvl1("Generated a sig")
	}
}


