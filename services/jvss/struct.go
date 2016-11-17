package jvss_service

import (
	"github.com/dedis/cothority/sda"
	"github.com/dedis/crypto/abstract"
)

type SignatureRequest struct {
	Message []byte
	Roster  *sda.Roster
}

type SignatureResponse struct {
	Signature *JVSSSig
}

type SetupRequest struct {
	Roster *sda.Roster
}

type SetupResponse struct {
	PublicKey *abstract.Point
}
