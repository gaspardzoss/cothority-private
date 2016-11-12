package jvss_round

import (
	"testing"
	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/protocols/jvss/jvss_setup"
	"github.com/sriak/crypto/poly"
	"github.com/sriak/cothority/protocols/jvss/jvss_round"
)


func TestJVSS_ROUND(t *testing.T) {
	// Setup parameters
	const TestProtocolName = "JVSS_SETUP_DUMMY" // Protocol name
	const TestRoundName = "JVSS_ROUND_DUMMY"
	var nodes uint32 = 5     // Number of nodes
	msg := []byte("Hello world")
	sharedSecretLongTermChan := make(chan *poly.SharedSecret)

	log.SetDebugVisible(1)

	sda.GlobalProtocolRegister(TestRoundName, func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		return jvss_round.NewJVSS_round(n, nil)
	})
	sda.GlobalProtocolRegister(TestProtocolName, func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		return jvss_setup.NewJVSS_setup(n, sharedSecretLongTermChan)
	})

	local := sda.NewLocalTest()
	_, _, tree := local.GenTree(int(nodes), false)
	defer local.CloseAll()

	log.Lvl1("JVSS Setup - starting")
	leader, err := local.CreateProtocol(TestProtocolName, tree)
	if err != nil {
		t.Fatal("Couldn't initialise protocol tree:", err)
	}
	numSecrets := 0
	secrets := make([]*poly.SharedSecret,0)
	go func(){
		for secret := range sharedSecretLongTermChan {
			secrets = append(secrets,secret)
			numSecrets++
		}
	}()

	leader.Start()
	log.Lvl1("JVSS - setup done")
	if(numSecrets != int(nodes)) {
		t.Fatalf("Didn't received enough secrets, expected %d got %d",nodes,numSecrets)
	}

	local = sda.NewLocalTest()
	_, _, tree = local.GenTree(int(nodes), false)
	if err != nil {
		t.Fatal("Couldn't initialise protocol tree:", err)
	}

	pi, err := local.CreateProtocol(TestRoundName, tree)
	if err != nil {
		t.Fatal("Couldn't initialise protocol tree:", err)
	}
	jvss_round := pi.(*jvss_round.JVSS_ROUND)
	jvss_round.Sign(msg)
}