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

type RepositorySC struct {
	repositoryName string
}

// If no skipchain for PackageName is found, both first and last are nil.
// If the skipchain has been found, both the genesis-block and the latest
// block will be returned.
type RepositorySCRet struct {
	First *skipchain.SkipBlock
	Last  *skipchain.SkipBlock
}

// Request skipblocks needed to get to the latest version of the repository.
// LastKnownSB is the latest skipblock known to the client.
type LatestBlock struct {
	LastKnownSB skipchain.SkipBlockID
}

// Returns the timestamp of the latest skipblock, together with an eventual
// shortes-link of skipblocks needed to go from the LastKnownSB to the
// current skipblock.
type LatestBlockRet struct {
	Timestamp *Timestamp
	Update    []*skipchain.SkipBlock
}
