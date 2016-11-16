#!/bin/bash

echo "=== Creating a new temporary gnupg keyring ==="
mkdir /tmp/gnupg
echo "=== Running go tests ==="
go test
echo "=== Importing keys ==="
gpg2 --homedir /tmp/gnupg --allow-non-selfsigned-uid --import testPubKey.pgp
gpg2 --homedir /tmp/gnupg --allow-non-selfsigned-uid --import testPubKeyJVSS.pgp
echo "=== Verifying gnupg signature ==="
gpg2 --homedir /tmp/gnupg --allow-non-selfsigned-uid --ignore-time-conflict --verify text.sig
echo $?
echo "=== Verifying jvss signature ==="
gpg2 --homedir /tmp/gnupg --allow-non-selfsigned-uid --ignore-time-conflict --verify textJVSS.sig
echo "=== Removing test files ==="
rm -f text textJVSS testPubKeyJVSS.pgp testPubKey.pgp textJVSS.sig text.sig
rm -rf /tmp/gnupg
