package setup_and_round

import (
	"sync"
	"testing"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/protocols/jvss/setup_and_round"
	"github.com/dedis/cothority/sda"
	"github.com/sriak/crypto/poly"
	"github.com/stretchr/testify/require"
)

func TestJVSS_ROUND(t *testing.T) {
	log.TestOutput(true, 2)
	// Setup parameters
	const TestProtocolName = "JVSS_SETUP_DUMMY" // Protocol name
	const TestRoundName = "JVSS_ROUND_DUMMY"
	var nodes uint32 = 5 // Number of nodes
	msg := []byte("Hello world")

	local := sda.NewLocalTest()
	hosts, _, tree := local.GenTree(int(nodes), false)
	defer local.CloseAll()

	sda.GlobalProtocolRegister(TestRoundName, func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		return NewJVSS_round(n, nil)
	})

	sharedLongtermSecrets := make([]*poly.SharedSecret, len(hosts))
	var wg sync.WaitGroup
	wg.Add(len(hosts))
	for i, h := range hosts {
		longTerm := make(chan *poly.SharedSecret)
		go func(j int, ltCh chan *poly.SharedSecret) {
			longterm := <-ltCh
			sharedLongtermSecrets[j] = longterm
			log.Print("Host", hosts[j].Address(), "generated longterm:", *longterm.Share)
			wg.Done()
		}(i, longTerm)

		h.ProtocolRegister(TestProtocolName, func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
			return setup_and_round.NewJVSS_setup(n, longTerm)
		})

	}

	log.Lvl1("JVSS Setup - starting")
	leader, err := local.CreateProtocol(TestProtocolName, tree)
	if err != nil {
		t.Fatal("Couldn't initialise protocol tree:", err)
	}

	leader.Start()
	wg.Wait()
	log.Lvl1("JVSS - setup done")

	for i, host := range hosts {
		lt := sharedLongtermSecrets[i]
		host.ProtocolRegister(TestRoundName, func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
			log.Print("Giving longterm to ", n.Name(), " longterm: ", *lt.Share)
			return NewJVSS_round(n, lt)
		})
	}

	pi, err := local.CreateProtocol(TestRoundName, tree)
	if err != nil {
		t.Fatal("Couldn't initialise protocol tree:", err)
	}
	jvss_round := pi.(*JVSS_ROUND)
	sig, err := jvss_round.Sign(msg)
	require.Nil(t, err)
}
