package jvss

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/sda"
)

var pubKey, _ = hex.DecodeString("d2a4f14e5d960f25117b36fb566254ab6a0371369de59e0b57bbbb62d6205cd8")
var R, _ = hex.DecodeString("f313141c35382feee107ef5e435fb7385722efc976deef0596b390cc98d4a6d1")
var S, _ = hex.DecodeString("8b435cbc47914cff4504fa6bcd885affb16b0f3a5e7c0c4944bd2c4bdbccbf0b")

var data = []byte("Hello world")

func TestPubKey(t *testing.T) {
	buffer := bytes.NewBuffer(nil)
	err := SerializePubKey(buffer, pubKey, "raph@raph.com")
	if err != nil {
		t.Fatal("Couldn't serialize public key: ", err)
	}
	err = ioutil.WriteFile("testPubKey.pgp", buffer.Bytes(), 0644)
	if err != nil {
		t.Fatal("Couldn't write public key: ", err)
	}
	log.Lvl1("Wrote public key file")
}

func TestSignature(t *testing.T) {
	buffer := bytes.NewBuffer(nil)
	err := SerializeSignature(buffer, data, pubKey, R, S)
	if err != nil {
		t.Fatal("Couldn't serialize signature: ", err)
	}
	err = ioutil.WriteFile("text.sig", buffer.Bytes(), 0644)
	if err != nil {
		t.Fatal("Couldn't write signature: ", err)
	}
	log.Lvl1("Wrote signature file")
	err = ioutil.WriteFile("text", data, 0644)
	if err != nil {
		t.Fatal("Couldn't write text file: ", err)
	}
	log.Lvl1("Wrote text file")
}

func TestJVSSPubKeyAndSignature(t *testing.T) {
	var name string = "JVSS" // Protocol name
	var nodes uint32 = 5     // Number of nodes

	msg := []byte("Hello world")
	hasher := sha256.New()
	msg = HashMessage(hasher, msg)
	log.Lvl1("Hashing " + hex.EncodeToString(msg))

	local := sda.NewLocalTest()
	_, _, tree := local.GenTree(int(nodes), false)
	defer local.CloseAll()

	log.Lvl1("JVSS - starting")
	leader, err := local.CreateProtocol(name, tree)
	if err != nil {
		t.Fatal("Couldn't initialise protocol tree:", err)
	}
	jv := leader.(*JVSS)
	leader.Start()
	log.Lvl1("JVSS - setup done")

	log.Lvl1("JVSS - starting round")
	log.Lvl1("JVSS - requesting signature")
	sig, err := jv.Sign(msg)
	if err != nil {
		t.Fatal("Error signature failed", err)
	}

	// Dirty "trick" to get longterm public secret
	var sidLTSS SID
	for k := range jv.sidStore.store {
		if strings.Contains(string(k), "LTSS") {
			sidLTSS = k
		}
	}

	sec, err := jv.secrets.secret(sidLTSS)
	if err != nil {
		t.Fatal("Couldn't get longterm secret :", err)
	}
	secPubB, err := sec.secret.Pub.SecretCommit().MarshalBinary()
	buffer := bytes.NewBuffer(nil)
	err = SerializePubKey(buffer, secPubB, "raph@raph.com")
	if err != nil {
		t.Fatal("Couldn't serialize public key: ", err)
	}
	secPubBDeserialized, err := DeSerializePubKey(bytes.NewReader(buffer.Bytes()))

	log.ErrFatal(err)
	if(!bytes.Equal(secPubB,secPubBDeserialized)) {
		t.Fatal("Deserialized didn't work")
	}
	err = ioutil.WriteFile("testPubKeyJVSS.pgp", buffer.Bytes(), 0644)
	if err != nil {
		t.Fatal("Couldn't write public key: ", err)
	}
	log.Lvl1("Wrote public key file")
	buffer.Reset()
	err = SerializePubKeyToArmor(buffer, secPubB, "raph@raph.com")
	if err != nil {
		t.Fatal("Couldn't serialize public key: ", err)
	}
	secPubArmorBDeserialized, err := DeSerializeArmoredPubKey(bytes.NewReader(buffer.Bytes()))
	log.ErrFatal(err)
	if(!bytes.Equal(secPubB,secPubArmorBDeserialized)) {
		t.Fatal("Deserialized didn't work")
	}
	err = ioutil.WriteFile("testPubKeyJVSS.asc", buffer.Bytes(), 0644)
	log.Lvl1("Wrote public key file to armor")


	r, _ := sig.Random.SecretCommit().MarshalBinary()
	s, _ := (*sig.Signature).MarshalBinary()

	buffer.Reset()
	err = SerializeSignature(buffer, msg, secPubB, r, s)
	if err != nil {
		t.Fatal("Couldn't serialize signature: ", err)
	}
	err = ioutil.WriteFile("textJVSS.sig", buffer.Bytes(), 0644)
	if err != nil {
		t.Fatal("Couldn't write public key: ", err)
	}
	log.Lvl1("Wrote signature file")
	buffer.Reset()
	err = SerializeSignatureToArmor(buffer, msg, secPubB, r, s)
	if err != nil {
		t.Fatal("Couldn't serialize signature: ", err)
	}
	err = ioutil.WriteFile("textJVSS.asc", buffer.Bytes(), 0644)
	if err != nil {
		t.Fatal("Couldn't write public key: ", err)
	}
	log.Lvl1("Wrote signature file armor")
	err = ioutil.WriteFile("textJVSS", data, 0644)
	if err != nil {
		t.Fatal("Couldn't text file: ", err)
	}
	log.Lvl1("Wrote text file")

	log.Lvl1("JVSS - signature received")
}
