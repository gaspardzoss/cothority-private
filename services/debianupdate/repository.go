package debianupdate

import (
	"github.com/dedis/cothority/log"

	"bufio"
	"compress/gzip"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"sync"
)

/*
 * Implement a Debian Repository containing packages
 */

type Repository struct {
	Origin    string
	Suite     string
	Version   string
	Packages  PackageSlice
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
		} else if strings.Contains(line, "Archive:") {
			repository.Suite = strings.Replace(line, "Archive: ", "", 1)
		} else if strings.Contains(line, "Version:") {
			repository.Version = strings.Replace(line, "Version: ", "", 1)
		}
	}
	file_p, err := os.Open(packagesFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file_p.Close()
	gr, err := gzip.NewReader(file_p)
	if err != nil {
		log.Fatal(err)
	}
	defer gr.Close()

	scanner := bufio.NewScanner(gr)
	log.ErrFatal(err)

	packageString := ""

	for scanner.Scan() {
		line := scanner.Text()

		if line != "" && line != "" && line != "\n" {
			packageString += line + "\n"
		} else {
			// TODO go repository.AddPackage(packageString) with chan instead of mutex
			repository.AddPackage(packageString)
			packageString = ""
		}
	}

	if len(packageString) != 0 {
		repository.AddPackage(packageString)
		packageString = ""
	}

	sort.Sort(repository.Packages)

	/*for _, p := range repository.Packages {
		log.Print(p)
	}*/

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
