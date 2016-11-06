package jvss_round

import (
	"testing"
	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/protocols/jvss/jvss_setup"
	"github.com/sriak/crypto/poly"
)


func TestJVSS_ROUND(t *testing.T) {
	// Setup parameters
	const TestProtocolName = "JVSS_SETUP_DUMMY" // Protocol name
	var nodes uint32 = 5     // Number of nodes
	msg := []byte("Hello world")
	sharedSecretLongTermChan := make(chan *poly.SharedSecret)

	log.SetDebugVisible(1)

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
	var jv_round_leader sda.ProtocolInstance = nil
	for i,node := range local.GetNodes(tree.Root) {
		log.LLvl1("i=",i)
		if(i == 0){
			jv_round_leader,err = NewJVSS_round(node,secrets[0])
		}
		NewJVSS_round(node,secrets[i])
	}
	jv_round := jv_round_leader.(*JVSS_ROUND)
	jv_round.Sign(msg)
}