package jvss_service

import (
	"github.com/dedis/cothority/sda"
	"github.com/sriak/crypto/poly"
	"github.com/dedis/cothority/protocols/jvss/jvss_setup"
	"github.com/dedis/cothority/protocols/jvss/jvss_round"
	"errors"
	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/network"
	"encoding/hex"
)

// ServiceName can be used to refer to the name of this service
const ServiceName = "JVSSService"
const JVSS_SETUP = "JVSS_setup"
const JVSS_ROUND = "JVSS_round"

func init()  {
	sda.RegisterNewService(ServiceName,newJVSSService)
}

// Service make a persistent jvss protocol
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*sda.ServiceProcessor
	path string
	sharedSecretchan chan *poly.SharedSecret
	//// Shared secret of node
	secret *poly.SharedSecret
}


func (s *Service) SignatureRequest(e *network.ServerIdentity, req *SignatureRequest) (network.Body,error){
	tree := req.Roster.GenerateBinaryTree()
	pi, err := s.CreateProtocolSDA(JVSS_ROUND, tree)
	if err != nil {
		return nil,errors.New("Couldn't create new node: " + err.Error())
	}
	// Register the function generating the protocol instance
	root := pi.(*jvss_round.JVSS_ROUND)
	sig, err := root.Sign(req.Message)
	return &SignatureResponse{sig},nil
}

func (s *Service) SetupRequest(e *network.ServerIdentity, req *SetupRequest)  (network.Body,error){
	tree := req.Roster.GenerateBinaryTree()
	pi, err := s.CreateProtocolSDA(JVSS_SETUP,tree)
	if err != nil {
		return nil,errors.New("Couldn't create new node: " + err.Error())
	}
	pi.Start()
	return nil,nil
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
		sharedSecretchan: make(chan *poly.SharedSecret,1),
	}

	go func() {
		s.secret = <- s.sharedSecretchan
		b, _ := (*s.secret.Share).MarshalBinary()
		log.Lvl2("received secret: " + hex.EncodeToString(b))
	}()

	c.ProtocolRegister(JVSS_SETUP,func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		return jvss_setup.NewJVSS_setup(n,s.sharedSecretchan)
	})
	c.ProtocolRegister(JVSS_ROUND,func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		return jvss_round.NewJVSS_round(n,s.secret)
	})

	if err := s.RegisterMessages(s.SetupRequest, s.SignatureRequest); err != nil {
		log.ErrFatal(err, "Couldn't register messages")
	}
	return s
}