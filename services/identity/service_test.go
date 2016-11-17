package identity

import (
	"testing"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/sda"
	"github.com/stretchr/testify/assert"
	"github.com/dedis/cothority/network"
	"github.com/dedis/crypto/config"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestService_CreateIdentity2(t *testing.T) {
	local := sda.NewTCPTest()
	defer local.CloseAll()
	_, el, s := local.MakeHELS(5, identityService)
	service := s.(*Service)

	keypair := config.NewKeyPair(network.Suite)
	il := NewConfig(50, keypair.Public, "one")
	msg, err := service.CreateIdentity(nil, &CreateIdentity{il, el})
	log.ErrFatal(err)
	air := msg.(*CreateIdentityReply)
	data := air.Data
	id, ok := service.Identities[string(data.Hash)]
	assert.True(t, ok)
	assert.NotNil(t, id)
}

func TestSetupPGP_SignMessage(t *testing.T) {
	local := sda.NewTCPTest()
	defer local.CloseAll()
	_, el, _ := local.MakeHELS(5, identityService)
	identity := NewIdentity(el, 1, "anon")
	message := []byte("hello")
	identity.CreateIdentity()
	pub, err := identity.SetupPGP()
	log.ErrFatal(err)
	sig, err := identity.SignMessage(message)
	log.ErrFatal(err)
	log.ErrFatal(sig.Verify(network.Suite, *pub, message))
}
