# CISC - Cisc Identity SkipChain

## Description
Cisc is uses a personal blockchain handled by the cothority. It
 can store any key/value pairs, and has a special module for managing
 ssh-public-keys.

Based upon skipchains, cisc serves a data-block with different entries that can be handled by a number of devices who propose changes and cryptographically vote to approve or deny those changes. Different data-types exist that will interpret the data-block and offer a service.

Besides having devices that can vote on changes, simple followers can download the data-block and get cryptographically signed updates to that data-block to be sure of the authenticity of the new data-block.

For further convenience, a simple mechanism allows for grouping identities with a shared voting-power.

## Command reference
Cisc takes different commands and sub-commands with arguments. The main commands are:
  * Id - manages the identities this device is connected to
  * Data - handles the data of the identities this device is connected to
  * Ssh - interfaces the ssh-data of the identities
  * Kv - direct key/value pair editing

### cisc id
Each device can be connected to one identity but linked to multiple identities. You can manage the connections with cisc id followed by:
  * Create - asks the skipchain to create a new identity and returns its id#. It also connects to that identity.
  * Connect - will ask the devices of the remote skipwchain to vote on the inclusion of this device in the skipchain - each device can only be connected to one identity

For later:
  * Remove - removes the link to that skipchain - also needs to be voted upon
  * Follow - only follows an identity without voting power. Doesn’t need confirmation
  * Create - If the device is already connected to an identity, it links instead of connecting
  * Link - like connect, but all devices of the identity share one vote
The group-skipchains have to be defined.

### cisc data
Each identity, connected or linked, has data attached to it that can be updated, modified and voted upon. To modify the data, you need to use the appropriate commands (ssh and password). To update and vote, you can use cisc data followed by:
  * Update - fetches the latest data from all identities from the skipchain as well as all proposed data (the ones which are not yet voted upon)
  * List - updates and lists all data associated with all identities
  * Vote - sends a positive vote or a rejection for a specific update-proposition

### cisc ssh
The ssh-data-type allows for an easy handling of multiple ssh-identities over a range of devices. It uses the ~/.ssh/config to get the list of ssh-identities on this device. In addition to the usual configurations, each ssh-identity can be preceded by a commented line
```
#cisc - ID#
```
Which indicates what identity shall be used to follow that ssh-identity. This is useful for configuring groups of identities that share some hosts.

The different sub-commands for cisc ssh are:
  * Add - creates a new entry in the ~/.ssh/config file for a new host and proposes the new data
  * Del - removes an entry in the ~/.ssh/config file and proposes the new data
  * List - shows all connections for this device

### cisc kv
The kv-data-type simply holds a map of key/value pairs that are shared by all devices of the identity. This can be for example the login/password, where the password would be encrypted with a master-password of course.

cisc kv has the following subcommands:
  * List - returns a list of all keys pairs
  * Value - returns the value of a given key
  * Add - adds a key/value pair by proposing the new data to the identity
  * Rm - removes a key/value pair by proposing the new data to the identity
