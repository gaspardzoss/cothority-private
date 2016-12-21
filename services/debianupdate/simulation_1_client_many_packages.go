package debianupdate

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/cothority/crypto"
	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/services/timestamp"
	"strings"
	"time"
)

func init() {
	sda.SimulationRegister("DebianUpdateOneClient", NewOneClientSimulation)
}

type oneClientSimulation struct {
	sda.SimulationBFTree
	Packages           string // The packages installed
	PackagesLatestHash string // The latest hashes for the inst. packages
	Base               int
	Height             int
	Snapshots          string // All the snapshots filenames
	Releases           string // All the release filenames
}

func NewOneClientSimulation(config string) (sda.Simulation, error) {
	es := &oneClientSimulation{Base: 2, Height: 10}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

func (e *oneClientSimulation) Setup(dir string, hosts []string) (
	*sda.SimulationConfig, error) {

	sc := &sda.SimulationConfig{}
	e.CreateRoster(sc, hosts, 2000)
	err := e.CreateTree(sc)

	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (e *oneClientSimulation) Run(config *sda.SimulationConfig) error {
	packages := strings.Split(e.Packages, " ")
	packages_hashes := strings.Split(e.PackagesLatestHash, " ")
	snapshot_files := strings.Split(e.Snapshots, " ")
	release_files := strings.Split(e.Releases, " ")
	log.Print(packages[0], packages_hashes[0], snapshot_files[0], release_files[0])

	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", e.Rounds)

	c := timestamp.NewClient()
	maxIterations := 0
	_, err := c.SetupStamper(config.Roster, time.Millisecond*250, maxIterations)
	if err != nil {
		return nil
	}

	service, ok := config.GetService(ServiceName).(*DebianUpdate)
	if service == nil || !ok {
		log.Fatal("Didn't find service", ServiceName)
	}
	//releases := make(map[string]*RepositoryChain)
	//repos := []*Repository{}
	repos := make(map[string]*RepositoryChain)
	releases := make(map[string]*Release)
	log.Lvl1("Loading repos")
	for i, release_file := range release_files {
		log.Lvl1("Parsing repo ", release_file)
		repo, err := NewRepository("/home/ouate/Developer/go/src/github.com/dedis/cothority/services/debianupdate/script/"+release_file,
			"/home/ouate/Developer/go/src/github.com/dedis/cothority/services/debianupdate/script/"+snapshot_files[i],
			"https://snapshots.debian.org")
		log.ErrFatal(err)
		hashes := make([]crypto.HashID, len(repo.Packages))
		for i, p := range repo.Packages {
			hashes[i] = crypto.HashID(p.Hash)
		}
		root, proofs := crypto.ProofTree(HashFunc(), hashes)
		release := &Release{repo, root, proofs}
		sc, knownRepo := repos[repo.GetName()]
		if knownRepo {
			urr, _ := service.UpdateRepository(nil,
				&UpdateRepository{sc, release})
			repos[repo.GetName()] = urr.(*UpdateRepositoryRet).RepositoryChain
			releases[repo.GetName()] = release
		} else {
			log.Print(config.Roster)
			cr, err := service.CreateRepository(nil,
				&CreateRepository{config.Roster, release, e.Base, e.Height})
			if err != nil {
				return err
			}
			repos[repo.GetName()] = cr.(*CreateRepositoryRet).RepositoryChain
			releases[repo.GetName()] = release
		}
		log.Print(repo.GetName())
		log.Print(release.RootID)
	}
	log.Lvl1("Loading repos - done")

	repoSCret, err := service.RepositorySC(nil, &RepositorySC{"Debian-stable"})
	log.ErrFatal(err)
	sc := repoSCret.(*RepositorySCRet).Last
	log.Print(sc.Hash)

	//releases := make(map[string]*Release)
	//updateClient := ...
	//timeClient := timestamp.NewClient()

	return nil
}
