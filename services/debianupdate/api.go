package debianupdate

import (
	"errors"
	"github.com/dedis/cothority/crypto"
	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/services/skipchain"
	"reflect"
)

type Client struct {
	*sda.Client
	Roster *sda.Roster
	//ProjectID
	Root *network.ServerIdentity
}

func NewClient(r *sda.Roster) *Client {
	return &Client{
		Client: sda.NewClient(ServiceName),
		Roster: r,
		Root:   r.List[0],
	}
}

func (c *Client) LatestUpdates(latestIDs []skipchain.SkipBlockID) (*LatestBlocksRet,
	error) {
	lbs := &LatestBlocks{latestIDs}
	p, err := c.Send(c.Root, lbs)
	if err != nil {
		return nil, err
	}

	lbr, ok := p.Msg.(LatestBlocksRetInternal)
	if !ok {
		return nil, errors.New("Wrong Message" + reflect.TypeOf(p.Msg).String())
	}
	var updates [][]*skipchain.SkipBlock
	for _, l := range lbr.Lengths {
		updates = append(updates, lbr.Updates[0:l])
		lbr.Updates = lbr.Updates[l:]
	}
	return &LatestBlocksRet{lbr.Timestamp, updates}, nil
}

func (c *Client) LatestUpdatesForRepo(repoName string) (*LatestBlockRet, error) {
	lbs := &LatestBlockRepo{repoName}
	p, err := c.Send(c.Root, lbs)
	if err != nil {
		return nil, err
	}

	lbr, ok := p.Msg.(LatestBlockRet)
	if !ok {
		return nil, errors.New("Wrong Message " + reflect.TypeOf(p.Msg).String())
	}
	return &lbr, nil
}

func (c *Client) TimestampRequests(names []string) (*TimestampRets, error) {
	t := &TimestampRequests{names}
	r, err := c.Send(c.Root, t)
	if err != nil {
		return nil, err
	}
	tr, ok := r.Msg.(TimestampRets)
	if !ok {
		return nil, errors.New("Wrong Message")
	}
	return &tr, nil
}

func (c *Client) LatestRelease(repo string) (*LatestRelease, error) {

	// First we gather the latest skipblock
	lbr, err := c.LatestUpdatesForRepo(repo)
	if err != nil {
		return nil, err
	}

	// we extract the release
	_, r, err := network.UnmarshalRegistered(lbr.Update[0].Data)

	if err != nil {
		return nil, err
	}

	// from the release we extract the packages names + hashes + proofs
	release := r.(*Release)

	proofs := release.Proofs
	lengths := release.ProofsLength
	packages := release.Repository.Packages

	packageProofHash := map[string]PackageProof{}

	log.Lvl2("preparing the datas")
	for i, p := range packages {
		flatproof := crypto.Proof{}
		for _, subproof := range proofs[:lengths[i]] {
			flatproof = append(flatproof, subproof...)
		}
		packageProofHash[p.Name] = PackageProof{p.Hash, flatproof}
		proofs = proofs[lengths[i]:]
	}

	// We need to return the root signed
	return &LatestRelease{release.RootID, packageProofHash}, nil
}
