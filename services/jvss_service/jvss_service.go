package jvss_service

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/protocols/jvss/jvss_round"
	"github.com/dedis/cothority/protocols/jvss/jvss_setup"
	"github.com/dedis/cothority/sda"
	"github.com/sriak/crypto/poly"
)

// ServiceName can be used to refer to the name of this service
const ServiceName = "JVSSService"
const JVSS_SETUP = "JVSS_setup"
const JVSS_ROUND = "JVSS_round"

func init() {
	sda.RegisterNewService(ServiceName, newJVSSService)
	//sda.GlobalProtocolRegister(JVSS_ROUND,func (n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
	//	return jvss_round.NewJVSS_round(n,nil)
	//});
}

// Service make a persistent jvss protocol
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*sda.ServiceProcessor
	path             string
	sharedSecretchan chan *poly.SharedSecret
	// Longterm Shared secret of node
	secret *poly.SharedSecret
}

func (s *Service) SignatureRequest(e *network.ServerIdentity, req *SignatureRequest) (network.Body, error) {
	tree := req.Roster.GenerateBinaryTree()
	log.Lvl2("Creating jvss round protocol instance")
	pi, err := s.CreateProtocolSDA(JVSS_ROUND, tree)
	if err != nil {
		return nil, errors.New("Couldn't create new node: " + err.Error())
	}
	log.Lvl2("Getting root node")
	root := pi.(*jvss_round.JVSS_ROUND)
	sig, err := root.Sign(req.Message)
	return &SignatureResponse{sig}, nil
}

func (s *Service) SetupRequest(e *network.ServerIdentity, req *SetupRequest) (network.Body, error) {
	tree := req.Roster.GenerateBinaryTree()
	pi, err := s.CreateProtocolSDA(JVSS_SETUP, tree)
	if err != nil {
		return nil, errors.New("Couldn't create new node: " + err.Error())
	}
	pi.Start()
	log.Lvl2("Setup done")
	return nil, nil
}

func (s *Service) save() {
	log.Lvl3("Saving service")
	b, err := network.MarshalRegisteredType(s.secret)
	if err != nil {
		log.Error("Couldn't marshal service:", err)
	} else {
		err = ioutil.WriteFile(s.path+"/secret.bin", b, 0660)
		if err != nil {
			log.Error("Couldn't save file:", err)
		}
	}
}

// Tries to load the configuration and updates if a configuration
// is found, else it returns an error.
func (s *Service) tryLoad() error {
	configFile := s.path + "/secret.bin"
	b, err := ioutil.ReadFile(configFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("Error while reading %s: %s", configFile, err)
	}
	if len(b) > 0 {
		_, msg, err := network.UnmarshalRegistered(b)
		if err != nil {
			return fmt.Errorf("Couldn't unmarshal: %s", err)
		}
		log.Lvl3("Successfully loaded")
		s.secret = msg.(*poly.SharedSecret)
	}
	return nil
}

func (s *Service) NewProtocol(tn *sda.TreeNodeInstance, conf *sda.GenericConfig) (sda.ProtocolInstance, error) {
	//switch tn.ProtocolName() {
	//case JVSS_SETUP:
	//	pi, err := jvss_setup.NewJVSS_setup(tn,s.sharedSecretchan)
	//	if err != nil {
	//		return nil, err
	//	}
	//	return pi,err
	//case JVSS_ROUND:
	//	pi, err := jvss_round.NewJVSS_round(tn,s.secret)
	//	if err != nil {
	//		return nil, err
	//	}
	//	return pi,err
	//}
	return nil, nil
}

func newJVSSService(c *sda.Context, path string) sda.Service {
	s := &Service{
		ServiceProcessor: sda.NewServiceProcessor(c),
		path:             path,
		sharedSecretchan: make(chan *poly.SharedSecret, 1),
		secret:           nil,
	}
	//if err := s.tryLoad(); err != nil {
	//	log.Error(err)
	//}

	go func() {
		s.secret = <-s.sharedSecretchan
		//s.save()
		log.Lvlf2("%s - received secret: %s", c.String(), *s.secret.Share)
	}()

	c.ProtocolRegister(JVSS_SETUP, func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		return jvss_setup.NewJVSS_setup(n, s.sharedSecretchan)
	})
	c.ProtocolRegister(JVSS_ROUND, func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		log.Print(c.String(), "JVSS ROUND with secret", *s.secret.Share)
		return jvss_round.NewJVSS_round(n, s.secret)
	})

	if err := s.RegisterMessages(s.SetupRequest, s.SignatureRequest); err != nil {
		log.ErrFatal(err, "Couldn't register messages")
	}
	return s
}
