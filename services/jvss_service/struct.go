package jvss_service

import (
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/network"
	"github.com/sriak/crypto/poly"
)

func init() {
	for _, msg := range []interface{}{
		SignatureRequest{},SignatureResponse{}, SetupRequest{},SetupResponse{},
	} {
		network.RegisterPacketType(msg)
	}
}

type SignatureRequest struct {
	Message []byte
	Roster  *sda.Roster
}

type SignatureResponse struct {
	sig *poly.SchnorrSig
}

type SetupRequest struct {
	Roster  *sda.Roster
}

type SetupResponse struct {
}
