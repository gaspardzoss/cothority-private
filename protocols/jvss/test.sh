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
echo "=== Reseting temporary gnupg keyring ==="
rm -rf /tmp/gnupg
mkdir /tmp/gnupg
echo "=== Importing armored keys ==="
gpg2 --homedir /tmp/gnupg --allow-non-selfsigned-uid --import testPubKeyJVSS.asc
echo "=== Verifying jvss armored signature ==="
gpg2 --homedir /tmp/gnupg --allow-non-selfsigned-uid --ignore-time-conflict --verify textJVSS.asc
echo "=== Removing test files ==="
rm -f text textJVSS testPubKeyJVSS.pgp testPubKey.pgp testPubKeyJVSS.asc textJVSS.sig text.sig textJVSS.asc 
rm -rf /tmp/gnupg
