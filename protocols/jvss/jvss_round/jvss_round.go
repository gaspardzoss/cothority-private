package jvss_round

import (
	"github.com/dedis/cothority/sda"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/abstract"
	"github.com/sriak/crypto/poly"
	"strings"
	"crypto/sha512"
	"fmt"
	"sync"
	"github.com/dedis/cothority/log"
	"crypto/rand"
	"encoding/base64"
)

// SID is the type of shared secret identifiers
type SID string

// Identifiers for long- and short-term shared secrets.
const (
	STSS SID = "STSS"
)

// randomLength is the length of random bytes that will be appended to SID to
// make them unique per signing requests
const randomLength = 32

// JVSS is the main protocol struct and implements the sda.ProtocolInstance
// interface.
type JVSS_ROUND struct {
	*sda.TreeNodeInstance                  // The SDA TreeNode
	keyPair               *config.KeyPair  // KeyPair of the host
	nodeList              []*sda.TreeNode  // List of TreeNodes in the JVSS group
	pubKeys               []abstract.Point // List of public keys of the above TreeNodes
	info                  poly.Threshold   // JVSS thresholds
	schnorr               *poly.Schnorr    // Long-term Schnorr struct to compute distributed signatures
	secrets               *sharedSecrets   // Shared secrets (short-term ones)

	shortTermSecDone chan bool // Channel to indicate when short-term shared secrets of all peers are ready

	sigChan chan *poly.SchnorrSig // Channel for JVSS signature

					       // keeps the set of SID this node has started/initiated
	sidStore *sidStore

}

// NewJVSS creates a new JVSS protocol instance and returns it.
func NewJVSS_round(node *sda.TreeNodeInstance, longterm *poly.SharedSecret) (sda.ProtocolInstance, error) {

	kp := &config.KeyPair{Suite: node.Suite(), Public: node.Public(), Secret: node.Private()}
	n := len(node.List())
	pk := make([]abstract.Point, n)
	for i, tn := range node.List() {
		pk[i] = tn.ServerIdentity.Public
	}
	// NOTE: T <= R <= N (for simplicity we use T = R = N; might change later)
	info := poly.Threshold{T: n, R: n, N: n}

	jv := &JVSS_ROUND{
		TreeNodeInstance: node,
		keyPair:          kp,
		pubKeys:          pk,
		info:             info,
		schnorr:          new(poly.Schnorr),
		secrets:          newSecrets(),
		shortTermSecDone: make(chan bool, 1),
		sigChan:          make(chan *poly.SchnorrSig),
		sidStore:         newSidStore(),
	}

	jv.schnorr.Init(jv.keyPair.Suite, jv.info, longterm)
	log.Lvlf4("Node %d: Schnorr struct initialised",
		jv.Index())


	// Setup message handlers
	h := []interface{}{
		jv.handleSecInit,
		jv.handleSecConf,
		jv.handleSigReq,
		jv.handleSigResp,
	}
	err := jv.RegisterHandlers(h...)
	if err != nil {
		return nil, err
	}
	return jv, err
}

// Start initiates the JVSS protocol by setting up a long-term shared secret
// which can be used later on by the JVSS group to sign and verify messages.
func (jv *JVSS_ROUND) Start() error {
	return nil
}

// Sign starts a new signing request amongst the JVSS group and returns a
// Schnorr signature on success.
func (jv *JVSS_ROUND) Sign(msg []byte) (*poly.SchnorrSig, error) {

	log.Lvl3(jv.Name(), "index", jv.Index(), " => Sign starting")

	// Initialise short-term shared secret only used for this signing request
	sid := newSID(STSS)
	jv.sidStore.insert(sid)
	if err := jv.initSecret(sid); err != nil {
		return nil, err
	}

	// Wait for setup of shared secrets to finish
	log.Lvl2("Waiting on short-term secrets:", jv.Name())
	<-jv.shortTermSecDone
	// Create partial signature ...
	ps, err := jv.sigPartial(sid, msg)
	if err != nil {
		return nil, err
	}

	// ... and buffer it
	secret, err := jv.secrets.secret(sid)
	if err != nil {
		log.Error("Didn't find secret. Still continuing:", err)
	}

	secret.sigs[jv.Index()] = ps

	// Broadcast signing request
	req := &SigReqMsg{
		Src: jv.Index(),
		SID: sid,
		Msg: msg,
	}
	if err := jv.Broadcast(req); err != nil {
		return nil, err
	}

	// Wait for complete signature
	sig := <-jv.sigChan

	return sig, nil
}

func (jv *JVSS_ROUND) initSecret(sid SID) error {
	// Initialise shared secret of given type if necessary
	if sec, err := jv.secrets.secret(sid); sec == nil && err != nil {
		log.Lvlf4("Node %d: Initialising %s shared secret", jv.Index(),
			sid)
		sec := &secret{
			receiver:         poly.NewReceiver(jv.keyPair.Suite, jv.info, jv.keyPair),
			deals:            make(map[int]*poly.Deal),
			sigs:             make(map[int]*poly.SchnorrPartialSig),
			numLongtermConfs: 0,
		}
		jv.secrets.addSecret(sid, sec)
	}

	secret, err := jv.secrets.secret(sid)
	if err != nil { // this should never happen here
		return err
	}

	// Initialise and broadcast our deal if necessary
	if len(secret.deals) == 0 {
		kp := config.NewKeyPair(jv.keyPair.Suite)
		deal := new(poly.Deal).ConstructDeal(kp, jv.keyPair, jv.info.T, jv.info.R, jv.pubKeys)
		log.Lvlf4("Node %d: Initialising %v deal", jv.Index(), sid)
		secret.deals[jv.Index()] = deal
		db, _ := deal.MarshalBinary()
		msg := &SecInitMsg{
			Src:  jv.Index(),
			SID:  sid,
			Deal: db,
		}
		if err := jv.Broadcast(msg); err != nil {
			return err
		}
	}
	return nil
}

func (jv *JVSS_ROUND) finaliseSecret(sid SID) error {
	secret, err := jv.secrets.secret(sid)
	if err != nil {
		return err
	}

	log.Lvlf4("Node %d: %s deals %d/%d", jv.Index(), sid, len(secret.deals),
		len(jv.List()))

	if len(secret.deals) == jv.info.T {

		for _, deal := range secret.deals {
			if _, err := secret.receiver.AddDeal(jv.Index(), deal); err != nil {
				return err
			}
		}

		sec, err := secret.receiver.ProduceSharedSecret()
		if err != nil {
			return err
		}
		secret.secret = sec
		isShortTermSecret := strings.HasPrefix(string(sid), string(STSS))
		if isShortTermSecret {
			secret.nShortConfirmsMtx.Lock()
			defer secret.nShortConfirmsMtx.Unlock()
			secret.numShortConfs++
		} else {
			secret.nLongConfirmsMtx.Lock()
			defer secret.nLongConfirmsMtx.Unlock()
			secret.numLongtermConfs++
		}

		log.Lvlf4("Node %d: %v created", jv.Index(), sid)

		// Broadcast that we have finished setting up our shared secret
		msg := &SecConfMsg{
			Src: jv.Index(),
			SID: sid,
		}
		if err := jv.Broadcast(msg); err != nil {
			return err
		}
	}
	return nil
}

func (jv *JVSS_ROUND) sigPartial(sid SID, msg []byte) (*poly.SchnorrPartialSig, error) {
	secret, err := jv.secrets.secret(sid)
	if err != nil {
		return nil, err
	}

	//hash := jv.keyPair.Suite.Hash()
	// TODO
	hash := sha512.New()
	//if _, err := hash.Write(msg); err != nil {
	//	return nil, err
	//}
	if err := jv.schnorr.NewRound(secret.secret, hash, msg); err != nil {
		return nil, err
	}
	ps := jv.schnorr.RevealPartialSig()
	if ps == nil {
		return nil, fmt.Errorf("Error, node %d could not create partial signature", jv.Index())
	}
	return ps, nil
}

// thread safe helpers for accessing shared (long and short-term) secrets:
type sharedSecrets struct {
	sync.Mutex
	secrets map[SID]*secret
}

func (s *sharedSecrets) secret(sid SID) (*secret, error) {
	s.Lock()
	defer s.Unlock()
	sec, ok := s.secrets[sid]
	if !ok {
		return nil, fmt.Errorf("Error, shared secret does not exist")
	}
	return sec, nil
}

func (s *sharedSecrets) addSecret(sid SID, sec *secret) {
	s.Lock()
	defer s.Unlock()
	s.secrets[sid] = sec
}

func (s *sharedSecrets) remove(sid SID) {
	s.Lock()
	defer s.Unlock()
	delete(s.secrets, sid)
}

func newSecrets() *sharedSecrets {
	return &sharedSecrets{secrets: make(map[SID]*secret)}
}

// secret contains all information for long- and short-term shared secrets.
type secret struct {
	secret   *poly.SharedSecret // Shared secret
	receiver *poly.Receiver     // Receiver to aggregate deals
				    // XXX potentially get rid of deals buffer later:
	deals map[int]*poly.Deal // Buffer for deals
				    // XXX potentially get rid of sig buffer later:
	sigs map[int]*poly.SchnorrPartialSig // Buffer for partial signatures

	// Number of collected confirmations that shared secrets are ready
	numLongtermConfs int
	nLongConfirmsMtx sync.Mutex

	// Number of collected (short-term) confirmations that shared secrets are ready
	numShortConfs     int
	nShortConfirmsMtx sync.Mutex
}

// newSID takes a TYPE of Secret,i.e. STSS or LTSS and append some random bytes
// to it
func newSID(t SID) SID {
	random := randomString(randomLength)
	return SID(string(t) + " - " + random)
}

// IsSTSS returns true if this SID is of type STSS - shorterm secret
func (s SID) IsSTSS() bool {
	return strings.HasPrefix(string(s), string(STSS))
}

// randomString will read n bytes from crypto/rand, will encode these bytes in
// base64 and returns the resulting string
func randomString(n int) string {
	var buff = make([]byte, n)
	_, err := rand.Read(buff)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString([]byte(buff))
}

// sidStore stores all sid in a thred safe manner
type sidStore struct {
	mutex sync.Mutex
	store map[SID]bool
}

func newSidStore() *sidStore {
	return &sidStore{
		store: make(map[SID]bool),
	}
}

// exists return true if the given sid is stored
// false otherwise.
func (s *sidStore) exists(sid SID) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, exists := s.store[sid]
	return exists
}

// insert will store the sid and returns true if it already existed before or
// false if the sid is a new entry.
func (s *sidStore) insert(sid SID) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, exists := s.store[sid]
	s.store[sid] = true
	return exists
}

// remove will delete the sid from the store and returns true if it was present
// or false otherwise
func (s *sidStore) remove(sid SID) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, exists := s.store[sid]
	delete(s.store, sid)
	return exists
}
