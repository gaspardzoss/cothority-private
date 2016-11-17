package jvss_service

import (
	"github.com/dedis/cothority/sda"
	"github.com/BurntSushi/toml"
)

func init() {
	sda.SimulationRegister("JVSSservice", NewSimulation)
}

// Simulation only holds the BFTree simulation
type simulation struct {
	sda.SimulationBFTree
}

// NewSimulation returns the new simulation, where all fields are
// initialised using the config-file
func NewSimulation(config string) (sda.Simulation, error) {
	es := &simulation{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (e *simulation) Setup(dir string, hosts []string) (
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
func (e *simulation) Run(config *sda.SimulationConfig) error {
	//size := config.Tree.Size()
	//msg := []byte("Test message for JVSS simulation")
	//log.Lvl2("Size is:", size, "rounds:", e.Rounds)
	//service, ok := config.GetService(ServiceName).(*Service)
	//if service == nil || !ok {
	//	log.Fatal("Didn't find service", ServiceName)
	//}
	//for round := 0; round < e.Rounds; round++ {
	//	log.Lvl1("Starting round", round)
	//	round := monitor.NewTimeMeasure("round")
	//	_, err := service.SetupRequest(nil, &SetupRequest{Roster: config.Roster})
	//	if err != nil {
	//		log.Error(err)
	//	}
	//	ret, err := service.SignatureRequest(nil, &SignatureRequest{Message: msg,Roster: config.Roster})
	//	if err != nil {
	//		log.Error(err)
	//	}
	//	resp, ok := ret.(*SignatureResponse)
	//	if !ok {
	//		log.Fatal("Didn't get a ClockResponse")
	//	}
	//	//log.Lvl1((*resp.sig.Signature).Bytes())
	//	round.Record()
	//}
	return nil
}