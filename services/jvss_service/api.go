package jvss_service

import (
	"github.com/dedis/cothority/sda"
	"github.com/sriak/crypto/poly"
	"github.com/dedis/cothority/network"
	"errors"
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

func (c *Client) Setup(r *sda.Roster) error {
	dst := r.RandomServerIdentity()
	reply, err := c.Send(dst,&SetupRequest{Roster: r})
	if e := network.ErrMsg(reply, err); e != nil {
		return e
	}
	return nil
}

func (c *Client) Sign(r *sda.Roster, msg []byte) (*poly.SchnorrSig,error) {
	dst := r.RandomServerIdentity()
	reply, err := c.Send(dst,&SignatureRequest{Message: msg, Roster: r})
	if e := network.ErrMsg(reply, err); e != nil {
		return nil, e
	}
	sig, ok := reply.Msg.(SignatureResponse)
	if !ok {
		return nil, errors.New("Wrong return-type.")
	}
	return sig.sig,nil
}
