package jvss_setup

import (
	"github.com/dedis/cothority/sda"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/abstract"
	"github.com/sriak/crypto/poly"
	"sync"
	"github.com/dedis/cothority/log"
)

//func init() {
//	sda.GlobalProtocolRegister("JVSS_SETUP", NewJVSS)
//}

// randomLength is the length of random bytes that will be appended to SID to
// make them unique per signing requests
const randomLength = 32

// JVSS is the main protocol struct and implements the sda.ProtocolInstance
// interface.
type JVSS_SETUP struct {
	*sda.TreeNodeInstance                  // The SDA TreeNode
	keyPair               *config.KeyPair  // KeyPair of the host
	nodeList              []*sda.TreeNode  // List of TreeNodes in the JVSS group
	pubKeys               []abstract.Point // List of public keys of the above TreeNodes
	info                  poly.Threshold   // JVSS thresholds

	longTermSecDone  chan bool // Channel to indicate when long-term shared secrets of all peers are ready

	sharedSecretLongTermChan chan *poly.SharedSecret

	sharedSecretLongTerm	*secret
}

// NewJVSS creates a new JVSS protocol instance and returns it.
func NewJVSS_setup(node *sda.TreeNodeInstance, secretChan chan *poly.SharedSecret) (sda.ProtocolInstance, error) {

	kp := &config.KeyPair{Suite: node.Suite(), Public: node.Public(), Secret: node.Private()}
	n := len(node.List())
	pk := make([]abstract.Point, n)
	for i, tn := range node.List() {
		pk[i] = tn.ServerIdentity.Public
	}
	// NOTE: T <= R <= N (for simplicity we use T = R = N; might change later)
	info := poly.Threshold{T: n, R: n, N: n}

	jv := &JVSS_SETUP{
		TreeNodeInstance: node,
		keyPair:          kp,
		pubKeys:          pk,
		info:             info,
		longTermSecDone:  make(chan bool, 1),
		sharedSecretLongTermChan: secretChan,
	}

	// Setup message handlers
	h := []interface{}{
		jv.handleSecInit,
		jv.handleSecConf,
	}
	err := jv.RegisterHandlers(h...)
	if err != nil {
		return nil, err
	}
	return jv, err
}

// Start initiates the JVSS protocol by setting up a long-term shared secret
// which can be used later on by the JVSS group to sign and verify messages.
func (jv *JVSS_SETUP) Start() error {
	log.Lvl2(jv.Name(), "index", jv.Index(), " Starts()")
	err := jv.initSecret()
	if err != nil {
		log.Error(err)
		return err
	}
	log.Lvl2("Waiting on long-term secrets:", jv.Name())
	<-jv.longTermSecDone
	log.Lvl2("Done waiting on long-term secrets:", jv.Name())
	return err
}

func (jv *JVSS_SETUP) initSecret() error {

	// Initialise shared secret if not already done
	if(jv.sharedSecretLongTerm == nil){
		jv.sharedSecretLongTerm = &secret{
			receiver:         poly.NewReceiver(jv.keyPair.Suite, jv.info, jv.keyPair),
			deals:            make(map[int]*poly.Deal),
			sigs:             make(map[int]*poly.SchnorrPartialSig),
			numLongtermConfs: 0,
		}
	}


	secret := jv.sharedSecretLongTerm

	// Initialise and broadcast our deal if necessary
	if len(secret.deals) == 0 {
		kp := config.NewKeyPair(jv.keyPair.Suite)
		deal := new(poly.Deal).ConstructDeal(kp, jv.keyPair, jv.info.T, jv.info.R, jv.pubKeys)
		log.Lvlf4("Node %d: Initialising deal", jv.Index())
		secret.deals[jv.Index()] = deal
		db, _ := deal.MarshalBinary()
		msg := &SecInitMsg{
			Src:  jv.Index(),
			Deal: db,
		}
		if err := jv.Broadcast(msg); err != nil {
			return err
		}
	}
	return nil
}

func (jv *JVSS_SETUP) finaliseSecret() error {
	secret := jv.sharedSecretLongTerm
	if secret == nil {
		log.Lvl4(jv.Index(), "Empty longterm secret")
		return nil
	}

	log.Lvlf4("Node %d: deals %d/%d", jv.Index(), len(secret.deals),
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
		secret.nLongConfirmsMtx.Lock()
		defer secret.nLongConfirmsMtx.Unlock()
		secret.numLongtermConfs++

		log.Lvlf2("Node %d: longterm created", jv.Index())
		// TODO check if best place to send it.
		jv.sharedSecretLongTermChan <- jv.sharedSecretLongTerm.secret
		// Broadcast that we have finished setting up our shared secret
		msg := &SecConfMsg{
			Src: jv.Index(),
		}
		if err := jv.Broadcast(msg); err != nil {
			return err
		}
	}
	return nil
}

func (jv *JVSS_SETUP) GetLongTermSecret() *poly.SharedSecret {
	return jv.sharedSecretLongTerm.secret
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
