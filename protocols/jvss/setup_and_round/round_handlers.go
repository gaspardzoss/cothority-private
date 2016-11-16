package setup_and_round

import (
	"github.com/dedis/cothority/log"
	"github.com/sriak/crypto/poly"
)

func (jv *JVSS_ROUND) handleSecInit(m WSecInitMsg) error {
	msg := m.SecInitMsg

	log.Lvl4(jv.Name(), jv.Index(), "Received SecInit from", m.TreeNode.Name())

	// Initialise shared secret
	if err := jv.initSecret(msg.SID); err != nil {
		return err
	}

	// Unmarshal received deal
	deal := new(poly.Deal).UnmarshalInit(jv.info.T, jv.info.R, jv.info.N, jv.keyPair.Suite)
	if err := deal.UnmarshalBinary(msg.Deal); err != nil {
		return err
	}

	// Buffer received deal for later
	secret, err := jv.secrets.secret(msg.SID)
	if err != nil {
		return err
	}
	secret.deals[msg.Src] = deal

	// Finalise shared secret
	if err := jv.finaliseSecret(msg.SID); err != nil {
		log.Error(jv.Index(), err)
		return err
	}
	log.Lvl4("Finished handleSecInit", jv.Name(), msg.SID)
	return nil
}

func (jv *JVSS_ROUND) handleSecConf(m WSecConfMsg) error {
	msg := m.SecConfMsg
	secret, err := jv.secrets.secret(msg.SID)
	if err != nil {
		log.Lvl2(jv.Index(), err, "for sid=", msg.SID)
		return nil
	}

	secret.nShortConfirmsMtx.Lock()
	defer secret.nShortConfirmsMtx.Unlock()
	secret.numShortConfs++

	// Check if we are the initiator node and have enough confirmations to proceed
	if secret.numShortConfs == len(jv.List()) && jv.sidStore.exists(msg.SID) {
		log.Lvl4("Writing to shortTermSecDone")
		jv.shortTermSecDone <- true
		secret.numShortConfs = 0
	} else {
		n := secret.numShortConfs
		log.Lvl4("Node %d: %s confirmations %d/%d", jv.Index(), msg.SID,
			n, len(jv.List()))
	}

	return nil
}

func (jv *JVSS_ROUND) handleSigReq(m WSigReqMsg) error {
	msg := m.SigReqMsg

	// Create partial signature
	ps, err := jv.sigPartial(msg.SID, msg.Msg)
	if err != nil {
		return err
	}

	// Send it back to initiator
	resp := &SigRespMsg{
		Src: jv.Index(),
		SID: msg.SID,
		Sig: ps,
	}

	if err := jv.SendTo(jv.List()[msg.Src], resp); err != nil {
		return err
	}

	// Cleanup short-term shared secret
	jv.secrets.remove(msg.SID)

	return nil
}

func (jv *JVSS_ROUND) handleSigResp(m WSigRespMsg) error {
	msg := m.SigRespMsg

	// Collect partial signatures
	secret, err := jv.secrets.secret(msg.SID)
	if err != nil {
		return err
	}

	secret.sigs[msg.Src] = msg.Sig

	log.Lvlf4("Node %d: %s signatures %d/%d", jv.Index(), msg.SID,
		len(secret.sigs), len(jv.List()))

	// Create Schnorr signature once we received enough partial signatures
	if jv.info.T == len(secret.sigs) {

		for _, sig := range secret.sigs {
			if err := jv.schnorr.AddPartialSig(sig); err != nil {
				return err
			}
		}

		sig, err := jv.schnorr.Sig()
		if err != nil {
			return err
		}
		jv.sigChan <- sig

		// Cleanup short-term shared secret
		jv.secrets.remove(msg.SID)
	}

	return nil
}
