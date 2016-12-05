package debianupdate

import (
	"io/ioutil"
	"strings"
	"sync"

	"github.com/dedis/cothority/log"
)

/*
 * Implement a Debian Repository containing packages
 */

type Repository struct {
	Origin    string
	Suite     string
	Version   string
	Keys      []string // the developers signing keys
	Threshold int      // the # of required dev
	Packages  []*Package
	SourceUrl string
	sync.Mutex
}

// NewRepository create a new repository from a release file, a packages file
// a keys file and a source url
func NewRepository(releaseFile string, packagesFile string, sourceUrl string) (*Repository, error) {

	release, err := ioutil.ReadFile(releaseFile)
	log.ErrFatal(err)

	repository := &Repository{SourceUrl: sourceUrl}

	for _, line := range strings.Split(string(release), "\n") {

		if strings.Contains(line, "Origin:") {
			repository.Origin = strings.Replace(line, "Origin: ", "", 1)
		} else if strings.Contains(line, "Suite:") {
			repository.Suite = strings.Replace(line, "Suite: ", "", 1)
		} else if strings.Contains(line, "Version:") {
			repository.Version = strings.Replace(line, "Version: ", "", 1)
		}
	}

	packages, err := ioutil.ReadFile(packagesFile)
	log.ErrFatal(err)

	packageString := ""

	for _, line := range strings.Split(string(packages), "\n") {

		if line != "\n" {
			packageString += line
		} else {
			go repository.AddPackage(packageString)
			packageString = ""
		}
	}

	return repository, nil
}

func (r *Repository) AddPackage(packageString string) {
	r.Lock()
	defer r.Unlock()
	p, err := NewPackage(packageString)
	log.ErrFatal(err)
	r.Packages = append(r.Packages, p)
}

func (r *Repository) GetName() string {
	return r.Origin + "-" + r.Suite
}
