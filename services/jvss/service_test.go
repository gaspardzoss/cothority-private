package jvss_service

import (
	"testing"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/protocols/jvss"
	"bytes"
	"io/ioutil"
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
	log.ErrFatal(err, "Couldn't send")
	if(sig == nil){
		t.Fatal("Sig was nil")
	}
	log.LLvlf1("Signature %s", sig.Signature)
	buffer := bytes.NewBuffer(nil)
	jvss.SerializePubKey(buffer, pub, "raph@raph.com")
	if err != nil {
		t.Fatal("Couldn't serialize public key: ", err)
	}
	err = ioutil.WriteFile("testPubKey.pgp", buffer.Bytes(), 0644)
	if err != nil {
		t.Fatal("Couldn't write public key: ", err)
	}
	log.Lvl1("Wrote public key file")
	//buffer = bytes.NewBuffer(nil)
	//err = jvss.SerializeSignature(buffer, msg, pub, r, s)
	//if err != nil {
	//	t.Fatal("Couldn't serialize signature: ", err)
	//}
	//err = ioutil.WriteFile("text.sig", buffer.Bytes(), 0644)
	//if err != nil {
	//	t.Fatal("Couldn't write signature: ", err)
	//}
	//log.Lvl1("Wrote signature file")
	//err = ioutil.WriteFile("text", msg, 0644)
	//if err != nil {
	//	t.Fatal("Couldn't write text file: ", err)
	//}
	//log.Lvl1("Wrote text file")

}


