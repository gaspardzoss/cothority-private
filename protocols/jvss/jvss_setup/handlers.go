package jvss_setup

import (
	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/sda"
	"github.com/sriak/crypto/poly"
)

// SecInitMsg are used to initialise new shared secrets both long- and
// short-term.
type SecInitMsg struct {
	Src  int
	Deal []byte
}

// SecConfMsg are used to confirm to other peers that we have finished setting
// up the shared secret.
type SecConfMsg struct {
	Src int
}

// WSecInitMsg is a SDA-wrapper around SecInitMsg.
type WSecInitMsg struct {
	*sda.TreeNode
	SecInitMsg
}

// WSecConfMsg is a SDA-wrapper around SecConfMsg.
type WSecConfMsg struct {
	*sda.TreeNode
	SecConfMsg
}

func (jv *JVSS_SETUP) handleSecInit(m WSecInitMsg) error {
	msg := m.SecInitMsg

	log.Lvl4(jv.Name(), jv.Index(), "Received SecInit from node", msg.Src)

	// Initialise shared secret
	if err := jv.initSecret(); err != nil {
		return err
	}

	// Unmarshal received deal
	deal := new(poly.Deal).UnmarshalInit(jv.info.T, jv.info.R, jv.info.N, jv.keyPair.Suite)
	if err := deal.UnmarshalBinary(msg.Deal); err != nil {
		return err
	}

	// Buffer received deal for later
	secret := jv.sharedSecretLongTerm
	if secret == nil {
		log.Lvl4(jv.Index(), "Empty longterm secret")
		return nil
	}
	secret.deals[msg.Src] = deal
	log.Lvl4(jv.Name(), jv.Index(), "Deals size", len(jv.sharedSecretLongTerm.deals))

	// Finalise shared secret
	if err := jv.finaliseSecret(); err != nil {
		log.Error(jv.Index(), err)
		return err
	}
	log.Lvl4("Finished handleSecInit", jv.Name())
	return nil
}

func (jv *JVSS_SETUP) handleSecConf(m WSecConfMsg) error {
	secret := jv.sharedSecretLongTerm
	if secret == nil {
		log.Lvl4(jv.Index(), "Empty longterm secret")
		return nil
	}

	secret.nLongConfirmsMtx.Lock()
	defer secret.nLongConfirmsMtx.Unlock()
	secret.numLongtermConfs++


	// Check if we are the initiator node and have enough confirmations to proceed
	if secret.numLongtermConfs == len(jv.List()) && jv.sharedSecretLongTerm != nil {
		log.Lvlf4("Node %d: got all confirmations, last from %d", jv.Index(),
			m.RosterIndex)
		log.Lvl4("Writing to longTermSecDone")
		jv.longTermSecDone <- true
		secret.numLongtermConfs = 0
	} else {
		n := secret.numLongtermConfs
		log.Lvlf4("Node %d: confirmations %d/%d, last from %d", jv.Index(),
			n, len(jv.List()),m.RosterIndex)
	}

	return nil
}

