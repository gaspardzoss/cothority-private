package jvss_service

import (
	"errors"

	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/sda"
	"github.com/sriak/crypto/poly"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/cothority/log"
)

func init()  {
	for _, msg := range []interface{}{
		&SignatureRequest{},
		&SignatureResponse{},
		&SetupRequest{},
		&SetupResponse{},
	} {
		network.RegisterPacketType(msg)
	}

}

// Client is a structure to communicate with the CoSi
// service
type Client struct {
	*sda.Client
}

// NewClient instantiates a new cosi.Client
func NewClient() *Client {
	return &Client{Client: sda.NewClient(ServiceName)}
}

func (c *Client) Setup(r *sda.Roster) (*abstract.Point, error) {
	dst := r.List[0]
	reply, err := c.Send(dst, &SetupRequest{Roster: r})
	if e := network.ErrMsg(reply, err); e != nil {
		return nil, e
	}
	pubKey, ok := reply.Msg.(SetupResponse)
	if !ok {
		return nil, errors.New("Wrong return-type.")
	}
	if(pubKey.PublicKey == nil) {
		return nil, errors.New("Public key was nil")
	}
	return pubKey.PublicKey, nil
}

func (c *Client) Sign(r *sda.Roster, msg []byte) (*poly.SchnorrSig, error) {
	dst := r.List[0]
	reply, err := c.Send(dst, &SignatureRequest{Message: msg, Roster: r})
	if e := network.ErrMsg(reply, err); e != nil {
		return nil, e
	}
	sig, ok := reply.Msg.(SignatureResponse)
	log.Lvlf1("Signature random commit %s", sig.Signature.Random.SecretCommit())
	if !ok {
		return nil, errors.New("Wrong return-type.")
	}
	if(sig.Signature == nil) {
		return nil, errors.New("Signature was nil")
	}
	return sig.Signature, nil
}
