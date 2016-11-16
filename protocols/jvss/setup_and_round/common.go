package setup_and_round

import (
	"github.com/sriak/crypto/poly"
	"github.com/dedis/cothority/sda"
	"sync"
)

// SecInitMsg are used to initialise new shared secrets both long- and
// short-term.
type SecInitMsg struct {
	Src  int
	SID  SID
	Deal []byte
}

// SecConfMsg are used to confirm to other peers that we have finished setting
// up the shared secret.
type SecConfMsg struct {
	Src int
	SID SID
}

// SigReqMsg are used to send signing requests.
type SigReqMsg struct {
	Src int
	SID SID
	Msg []byte
}

// SigRespMsg are used to reply to signing requests.
type SigRespMsg struct {
	Src int
	SID SID
	Sig *poly.SchnorrPartialSig
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

// WSigReqMsg is a SDA-wrapper around SigReqMsg.
type WSigReqMsg struct {
	*sda.TreeNode
	SigReqMsg
}

// WSigRespMsg is a SDA-wrapper around SigRespMsg.
type WSigRespMsg struct {
	*sda.TreeNode
	SigRespMsg
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