package swupdate

import (
	"encoding/hex"
	"fmt"
	"sync"

	"crypto/rand"
	"crypto/sha256"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/monitor"
	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/protocols/swupdate"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/services/skipchain"
	"github.com/dedis/cothority/services/timestamp"
)

/*
 * Defines the simulation for the service-template to be run with
 * `cothority/simul`.
 */

func init() {
	sda.SimulationRegister("SwUpFlood", NewFloodSimulation)
}

// Simulation holds the BFTree simulation and additional configurations.
type floodSimulation struct {
	sda.SimulationBFTree
	Requests int
	// If latest is true the latest block of the requested (debian) package
	// will be used. If latest fals the block where the package first got
	// into the skipchain will be used.
	Latest bool
}

// NewSimulation returns the new simulation, where all fields are
// initialised using the config-file
func NewFloodSimulation(config string) (sda.Simulation, error) {
	es := &floodSimulation{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (e *floodSimulation) Setup(dir string, hosts []string) (
	*sda.SimulationConfig, error) {
	sc := &sda.SimulationConfig{}
	e.CreateRoster(sc, hosts, 2000)
	err := e.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// Run is used on the destination machines and runs a number of
// rounds
func (e *floodSimulation) Run(config *sda.SimulationConfig) error {
	c := timestamp.NewClient()
	// TODO move all params to config file:
	maxIterations := 0
	_, err := c.SetupStamper(config.Roster, time.Second*2, maxIterations)
	if err != nil {
		return err
	}
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", e.Rounds)
	service, ok := config.GetService(ServiceName).(*Service)
	if service == nil || !ok {
		log.Fatal("Didn't find service", ServiceName)
	}
	// Get all packages
	log.Print("Before init pakages")
	packages, err := InitializePackages("../../../services/swupdate/snapshot/snapshots_nik.csv", service, config.Roster, 2, 10)
	log.ErrFatal(err)
	log.Print("After init packages")
	// Make a DOS-measurement of what the services can handle
	pscRaw, err := service.PackageSC(nil, &PackageSC{packages[0]})
	log.ErrFatal(err)
	psc := pscRaw.(*PackageSCRet)
	//log.Print(psc)
	wg := sync.WaitGroup{}
	var m *monitor.TimeMeasure
	var blockID skipchain.SkipBlockID
	if e.Latest {
		// Measure how long it takes to update from the latest block.
		m = monitor.NewTimeMeasure("update_empty")
		blockID = psc.Last.Hash
	} else {
		// Measure how long it takes to update from the first to the latest block.
		m = monitor.NewTimeMeasure("update_full")
		blockID = psc.First.Hash
	}
	for req := 0; req < e.Requests; req++ {
		wg.Add(1)
		go func() {
			runClientRequests(config, blockID, packages[0], service.Storage.SwupChains[packages[0]].Data.Hash)
			wg.Done()
		}()
	}
	wg.Wait()
	m.Record()

	return nil
}

func runClientRequests(config *sda.SimulationConfig, blockID skipchain.SkipBlockID, name string, proofID skipchain.SkipBlockID) {
	service, ok := config.GetService(ServiceName).(*Service)
	res, err := service.LatestBlock(nil, &LatestBlock{LastKnownSB: blockID})
	log.ErrFatal(err)
	lbret, ok := res.(*LatestBlockRet)
	if !ok {
		log.Fatal("Got invalid response.")
	}

	// Get Timestamp from timestamper.
	timeClient := timestamp.NewClient()
	// create nonce:
	r := make([]byte, 20)
	_, err = rand.Read(r)
	log.ErrFatal(err, "Couldn't read random bytes:")
	nonce := sha256.Sum256(r)

	root := config.Roster.List[0]
	// send request:
	resp, err := timeClient.SignMsg(root, nonce[:])
	log.ErrFatal(err, "Couldn't sign nonce.")

	// Verify the time is in the good range:
	ts := time.Unix(resp.Timestamp, 0)
	latesBlockTime := time.Unix(lbret.Timestamp.Timestamp, 0)
	if ts.Sub(latesBlockTime) > time.Hour {
		log.Warn("Timestamp of latest block is older than one hour!")
	}
	// verify proof of inclusion of the last skipblock of this package's chain
	// in the merkle tree of the timestamper included in the swupdate service.
	proofVeri := monitor.NewTimeMeasure("client_proof")
	res, err = service.LatestBlock(nil, &LatestBlock{LastKnownSB: proofID})
	log.ErrFatal(err)
	lbret, ok = res.(*LatestBlockRet)
	if !ok {
		log.Fatal("Got invalid response.")
	}
	leaf := lbret.Update[len(lbret.Update)-1].Hash
	//leaf := service.Storage.SwupChains[name].Data.Hash

	tr, err := service.TimestampProof(nil, &TimestampRequest{name})
	log.ErrFatal(err)
	proof := tr.(*TimestampRet).Proof
	if !proof.Check(HashFunc(), lbret.Timestamp.Root, leaf) {
		log.Warn("Proof of inclusion is not correct for", fmt.Sprintf("%s (%d)", hex.EncodeToString(leaf), len(leaf)), " (proofId ", fmt.Sprintf("%s (%d)", hex.EncodeToString(proofID), len(proofID)), ")")
	} else {
		log.Lvl2("Proof verification!")
	}

	// verify signature
	msg := MarshalPair(lbret.Timestamp.Root, lbret.Timestamp.SignatureResponse.Timestamp)
	err = swupdate.VerifySignature(network.Suite, config.Roster.Publics(), msg, lbret.Timestamp.SignatureResponse.Signature)
	if err != nil {
		log.Warn("Signature timestamp invalid")
	} else {
		log.Lvl2("Signature timestamp Valid :)")
	}
	proofVeri.Record()
}
