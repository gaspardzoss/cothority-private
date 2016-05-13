package identity

import (
	"bufio"

	"github.com/dedis/cothority/lib/network"
	"github.com/dedis/cothority/lib/sda"
	"github.com/dedis/cothority/services/skipchain"
	"github.com/dedis/cothority/lib/crypto"
)

/*
 */

func init() {
	for _, s := range []interface{}{
		&Owner{},
		&Identity{},
		&AccountList{},
		&AddIdentity{},
		&AddIdentityReply{},
		&AttachToIdentity{},
		&ConfigNewCheck{},
	} {
		network.RegisterMessageType(s)
	}
}

// Identity can both follow and update an IdentityList
type Identity struct {
	*sda.Client
	ID         IdentityID
	Config     *AccountList
	Proposed   *AccountList
	ManagerStr string
	SSHPub     string
	skipchain  *skipchain.Client
	cothority  *sda.EntityList
	root       *skipchain.SkipBlock
	data       *skipchain.SkipBlock
}

// NewIdentity starts a new identity that can contain multiple managers with
// different accounts
func NewIdentity(cothority *sda.EntityList, majority int, owner, sshPub string) *Identity {
	client := sda.NewClient(ServiceName)
	return &Identity{
		Client:     client,
		Config:     NewAccountList(majority, client.Public, owner, sshPub),
		ManagerStr: owner,
		SSHPub:     sshPub,
		cothority:  cothority,
		skipchain:  skipchain.NewClient(),
	}
}

// NewClientFromStream reads the configuration of that client from
// any stream
func NewIdentityFromStream(in bufio.Reader) (*Identity, error) {
	return nil, nil
}

// SaveToStream stores the configuration of the client to a stream
func (i *Identity) SaveToStream(out bufio.Writer) error {
	return nil
}

// AttachToIdentity proposes to attach it to an existing Identity
func (i *Identity) AttachToIdentity(ID IdentityID) error {
	i.ID = ID
	err := i.ConfigUpdate()
	if err != nil{
		return err
	}
	confPropose := i.Config.Copy()
	confPropose.Owners[i.ManagerStr] = &Owner{i.Entity.Public}
	confPropose.Data[i.Entity.Public] = i.SSHPub
	err = i.ConfigNewPropose(confPropose)
	if err != nil {
		return err
	}
	return nil
}

// CreateIdentity asks the identityService to create a new Identity
func (i *Identity) CreateIdentity() error {
	msg, err := i.Send(i.cothority.GetRandom(), &AddIdentity{i.Config, i.cothority})
	if err != nil {
		return err
	}
	air := msg.Msg.(AddIdentityReply)
	i.root = air.Root
	i.data = air.Data
	i.ID = IdentityID(i.data.Hash)

	return nil
}

// ConfigNewPropose collects new IdentityLists and waits for confirmation with
// ConfigNewVote
func (i *Identity) ConfigNewPropose(il *AccountList) error {
	_, err := i.SendToAll(i.cothority, &Proposition{i.ID, il})
	return err
}

// ConfigNewCheck verifies if there is a new configuration awaiting that
// needs approval from clients
func (i *Identity) ConfigNewCheck() error {
	msg, err := i.Send(i.cothority.GetRandom(), &ConfigNewCheck{
		ID:          i.ID,
		AccountList: nil,
	})
	if err != nil {
		return err
	}
	cnc := msg.Msg.(ConfigNewCheck)
	i.Proposed = cnc.AccountList
	return nil
}

// ConfigNewVote sends a vote (accept or reject) with regard to a new configuration
func (i *Identity) ConfigNewVote(configID crypto.HashID, accept bool) error {
	return nil
}

// ConfigUpdate asks if there is any new config available that has already
// been approved by others and updates the local configuration
func (i *Identity) ConfigUpdate() error {
	return nil
}
