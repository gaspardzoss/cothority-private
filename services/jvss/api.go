package jvss_service

import (
	"errors"

	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/sda"
	"github.com/sriak/crypto/poly"
)

// Client is a structure to communicate with the CoSi
// service
type Client struct {
	*sda.Client
}

// NewClient instantiates a new cosi.Client
func NewClient() *Client {
	return &Client{Client: sda.NewClient(ServiceName)}
}

func (c *Client) Setup(r *sda.Roster) ([]byte, error) {
	dst := r.List[0]
	reply, err := c.Send(dst, &SetupRequest{Roster: r})
	if e := network.ErrMsg(reply, err); e != nil {
		return nil, e
	}
	pubKey, ok := reply.Msg.(SetupResponse)
	if !ok {
		return nil, errors.New("Wrong return-type.")
	}
	return pubKey.publicKey, nil
}

func (c *Client) Sign(r *sda.Roster, msg []byte) (*poly.SchnorrSig, error) {
	dst := r.List[0]
	reply, err := c.Send(dst, &SignatureRequest{Message: msg, Roster: r})
	if e := network.ErrMsg(reply, err); e != nil {
		return nil, e
	}
	sig, ok := reply.Msg.(SignatureResponse)
	if !ok {
		return nil, errors.New("Wrong return-type.")
	}
	return sig.signature, nil
}
