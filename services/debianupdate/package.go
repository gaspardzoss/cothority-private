package debianupdate

import (
	"errors"
	"strings"
)

/*
 * Implement a Debian Package
 */

type Package struct {
	Name    string
	Version string
	Hash    string
}

// NewPackage takes an input string of the form
// Package: name
// Version: 1.0+blabla
// SHA256: SOMEHASH
// and some other fields
func NewPackage(packageString string) (*Package, error) {

	lines := strings.Split(packageString, "\n")
	if len(lines) < 3 {
		return nil, errors.New("Should have at least 3 lines " + packageString)
	}

	p := &Package{}

	for _, line := range lines {
		if strings.Contains(line, "Package:") {
			p.Name = strings.Replace(line, "Package: ", "", 1)
		} else if strings.Contains(line, "Version:") {
			p.Version = strings.Replace(line, "Version: ", "", 1)
		} else if strings.Contains(line, "SHA256:") {
			p.Hash = strings.Replace(line, "SHA256: ", "", 1)
		}

		// For this example, we only verify if these fields are valid
		// and we end the parsing as soon as all of them are filled.
		if p.Name != "" && p.Version != "" && p.Hash != "" {
			return p, nil
		}
	}

	return p, nil
}
