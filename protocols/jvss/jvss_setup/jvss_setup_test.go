package jvss_setup

import (
	"testing"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/log"
	"github.com/sriak/crypto/poly"
	"encoding/hex"
)

func TestJVSS_setup(t *testing.T) {
	// Setup parameters
	const TestProtocolName = "JVSS_SETUP_DUMMY" // Protocol name
	var nodes uint32 = 5     // Number of nodes
	sharedSecretLongTermChan := make(chan *poly.SharedSecret)

	log.SetDebugVisible(2)

	sda.GlobalProtocolRegister(TestProtocolName, func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		return NewJVSS_setup(n, sharedSecretLongTermChan)
	})

	local := sda.NewLocalTest()
	_, _, tree := local.GenTree(int(nodes), false)
	defer local.CloseAll()

	log.Lvl1("JVSS Setup - starting")
	leader, err := local.CreateProtocol(TestProtocolName, tree)
	if err != nil {
		t.Fatal("Couldn't initialise protocol tree:", err)
	}
	jv := leader.(*JVSS_SETUP)
	numSecrets := 0
	go func(){
		for secret := range sharedSecretLongTermChan {
			b, _ := (*secret.Share).MarshalBinary()
			log.Lvl1("Got secret " + hex.EncodeToString(b))
			numSecrets++
		}
	}()

	leader.Start()
	log.Lvl1("JVSS - setup done")
	secret := jv.GetLongTermSecret()
	if(secret == nil) {
		t.Fatal("Long term secret for root was nil")
	}
	if(numSecrets != int(nodes)) {
		t.Fatalf("Didn't received enough secrets, expected %d got %d",nodes,numSecrets)
	}

}
