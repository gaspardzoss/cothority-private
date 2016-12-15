package debianupdate

import (
	"github.com/dedis/cothority/crypto"
	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/services/skipchain"
	"github.com/dedis/cothority/services/timestamp"
	"github.com/satori/go.uuid"
)

func init() {
	for _, msg := range []interface{}{
		RepositoryChain{},
		CreateRepository{},
		CreateRepositoryRet{},
		UpdateRepository{},
		UpdateRepositoryRet{},
		Release{},
		Repository{},
	} {
		network.RegisterPacketType(msg)
	}
}

type ProjectID uuid.UUID

// Release is a Debian Repository and the developers' signatures
type Release struct {
	Repository *Repository
	RootID     crypto.HashID
	Proofs     []crypto.Proof
}

type RepositoryChain struct {
	Root    *skipchain.SkipBlock // The Root Skipchain
	Data    *skipchain.SkipBlock // The Data Skipchain
	Release *Release             // The Release (Repository) informations
}

type Timestamp struct {
	timestamp.SignatureResponse
	Proofs []crypto.Proof
}

type CreateRepository struct {
	Roster  *sda.Roster
	Release *Release
	Base    int
	Height  int
}

type CreateRepositoryRet struct {
	RepositoryChain *RepositoryChain
}

type UpdateRepository struct {
	RepositoryChain *RepositoryChain
	Release         *Release
}

type UpdateRepositoryRet struct {
	RepositoryChain *RepositoryChain
}
