package jvss_service

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"sync"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/protocols/jvss/setup_and_round"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/crypto/abstract"
	"github.com/sriak/crypto/poly"
)

// ServiceName can be used to refer to the name of this service
const ServiceName = "JVSSService"
const JVSS_SETUP = "JVSS_setup"
const JVSS_ROUND = "JVSS_round"

func init() {
	sda.RegisterNewService(ServiceName, newJVSSService)
	network.RegisterPacketType(&poly.SharedSecret{})
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
	secretMutex sync.Mutex
	secret      *poly.SharedSecret
}

type JVSSSig struct {
	Signature abstract.Scalar
	Random    abstract.Point
}

func (s *JVSSSig) Verify(suite abstract.Suite, public abstract.Point, msg []byte) error {
	// gamma * G
	left := suite.Point().Mul(nil, s.Signature)

	randomCommit := s.Random
	publicCommit := public
	h := sha512.New()
	if _, err := randomCommit.MarshalTo(h); err != nil {
		return err
	}
	if _, err := publicCommit.MarshalTo(h); err != nil {
		return err
	}
	h.Write(msg)
	buff := h.Sum(nil)
	hash := suite.Scalar().SetBytes(buff)
	// RandomSecretCommit + H(...) * LongtermSecretCommit
	right := suite.Point().Add(randomCommit, suite.Point().Mul(publicCommit, hash))
	if !left.Equal(right) {
		return errors.New("Signature could not have been verified against the message")
	}
	return nil
}

func (s *Service) SignatureRequest(e *network.ServerIdentity, req *SignatureRequest) (network.Body, error) {
	if(s.secret == nil) {
		return nil, errors.New("Must run setup before signing.")
	}
	tree := req.Roster.GenerateBinaryTree()
	log.Lvl2("Creating jvss round protocol instance")
	pi, err := s.CreateProtocolSDA(JVSS_ROUND, tree)
	if err != nil {
		return nil, errors.New("Couldn't create new node: " + err.Error())
	}
	log.Lvl2("Getting root node")
	root := pi.(*setup_and_round.JVSS_ROUND)
	sig, err := root.Sign(req.Message)
	jvssSig := &JVSSSig{
		Signature: *sig.Signature,
		Random:    sig.Random.SecretCommit(),
	}
	return &SignatureResponse{jvssSig}, nil
}

// TODO do setup every time ? Or only do if secret != nil ?
func (s *Service) SetupRequest(e *network.ServerIdentity, req *SetupRequest) (network.Body, error) {
	tree := req.Roster.GenerateBinaryTree()
	pi, err := s.CreateProtocolSDA(JVSS_SETUP, tree)
	if err != nil {
		return nil, errors.New("Couldn't create new node: " + err.Error())
	}
	pi.Start()
	log.Lvl2("Setup done")
	pubKey := s.secret.Pub.SecretCommit()
	return &SetupResponse{&pubKey}, nil
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
		log.Lvl2("Successfully loaded")
		s.secretMutex.Lock()
		s.secret = msg.(*poly.SharedSecret)
		s.secretMutex.Unlock()
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
	if err := s.tryLoad(); err != nil {
		log.Error(err)
	}

	go func() {
		s.secretMutex.Lock()
		defer s.secretMutex.Unlock()
		s.secret = <-s.sharedSecretchan
		s.save()
		log.Lvlf2("%s - received secret: %s", c.String(), *s.secret.Share)
	}()

	c.ProtocolRegister(JVSS_SETUP, func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		return setup_and_round.NewJVSS_setup(n, s.sharedSecretchan)
	})
	c.ProtocolRegister(JVSS_ROUND, func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		return setup_and_round.NewJVSS_round(n, s.secret)
	})

	if err := s.RegisterMessages(s.SetupRequest, s.SignatureRequest); err != nil {
		log.ErrFatal(err, "Couldn't register messages")
	}
	return s
}
