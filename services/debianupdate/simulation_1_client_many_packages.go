package debianupdate

import (
	"github.com/BurntSushi/toml"

	"errors"
	"github.com/dedis/cothority/crypto"
	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/monitor"
	"github.com/dedis/cothority/sda"
	"github.com/dedis/cothority/services/timestamp"
	"os"
	"sort"
	"time"
)

func init() {
	sda.SimulationRegister("DebianUpdateOneClient", NewOneClientSimulation)
}

type oneClientSimulation struct {
	sda.SimulationBFTree
	Base                      int
	Height                    int
	NumberOfInstalledPackages int
	Snapshots                 string // All the snapshots filenames
}

func NewOneClientSimulation(config string) (sda.Simulation, error) {
	es := &oneClientSimulation{Base: 2, Height: 10}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	//log.SetDebugVisible(3)
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
	err = CopyDir(dir, e.Snapshots)

	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (e *oneClientSimulation) Run(config *sda.SimulationConfig) error {

	// The cothority configuration
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", e.Rounds)

	// check if the service is running and get an handle to it
	service, ok := config.GetService(ServiceName).(*DebianUpdate)
	if service == nil || !ok {
		log.Fatal("Didn't find service", ServiceName)
	}

	// create and setup a new timestamp client
	c := timestamp.NewClient()
	maxIterations := 0
	_, err := c.SetupStamper(config.Roster, time.Millisecond*250, maxIterations)
	if err != nil {
		return nil
	}

	// get the release and snapshots
	current_dir, err := os.Getwd()

	if err != nil {
		return nil
	}
	snapshot_files, err := GetFileFromType(current_dir+"/"+e.Snapshots, "Packages")
	if err != nil {
		return nil
	}
	release_files, err := GetFileFromType(current_dir+"/"+e.Snapshots, "Release")
	if err != nil {
		return nil
	}

	sort.Sort(snapshot_files)
	sort.Sort(release_files)

	repos := make(map[string]*RepositoryChain)
	releases := make(map[string]*Release)

	updateClient := NewClient(config.Roster)

	var round *monitor.TimeMeasure

	log.Lvl2("Loading repository files")
	for i, release_file := range release_files {
		log.Lvl1("Parsing repo file", release_file)

		// Create a new repository structure (not a new skipchain..!)
		repo, err := NewRepository(release_file, snapshot_files[i],
			"https://snapshots.debian.org", e.Snapshots)
		log.ErrFatal(err)
		log.Lvl1("Repository created with", len(repo.Packages), "packages")

		// Recover all the hashes from the repo
		hashes := make([]crypto.HashID, len(repo.Packages))
		for i, p := range repo.Packages {
			hashes[i] = crypto.HashID(p.Hash)
		}

		// Compute the root and the proofs
		root, proofs := crypto.ProofTree(HashFunc(), hashes)
		lengths := []int64{}
		for _, proof := range proofs {
			lengths = append(lengths, int64(len(proof)))
		}
		// Store the repo, root and proofs in a release
		release := &Release{repo, root, proofs, lengths}

		// check if the skipchain has already been created for this repo
		sc, knownRepo := repos[repo.GetName()]

		if knownRepo {
			round = monitor.NewTimeMeasure("add_to_skipchain")

			log.Lvl1("A skipchain for", repo.GetName(), "already exists",
				"trying to add the release to the skipchain.")

			// is the new block different ?
			// who should take care of that ? the client or the server ?
			// I would say the server, when it receive a new release
			// it should check that it's different than the actual release
			urr, err := service.UpdateRepository(nil,
				&UpdateRepository{sc, release})

			if err != nil {
				log.Lvl1(err)
			} else {

				// update the references to the latest block and release
				repos[repo.GetName()] = urr.(*UpdateRepositoryRet).RepositoryChain
				releases[repo.GetName()] = release
			}
		} else {
			round = monitor.NewTimeMeasure("create_skipchain")

			log.Lvl2("Creating a new skipchain for", repo.GetName())

			cr, err := service.CreateRepository(nil,
				&CreateRepository{config.Roster, release, e.Base, e.Height})
			if err != nil {
				return err
			}

			// update the references to the latest block and release
			repos[repo.GetName()] = cr.(*CreateRepositoryRet).RepositoryChain
			releases[repo.GetName()] = release
		}
		round.Record()
	}
	log.Lvl2("Loading repository files - done")

	lr, err := updateClient.LatestRelease("Debian-jessie-updates")
	if err != nil {
		log.Lvl1(err)
		return nil
	}

	// Check signature on root

	// Verify proofs for installed packages
	round = monitor.NewTimeMeasure("verify_proofs")

	// take e.NumberOfInstalledPackages randomly insteand of the first

	log.Lvl1("Verifiying at most", e.NumberOfInstalledPackages, "packages")
	i := 1
	for name, p := range lr.Packages {
		hash := []byte(p.Hash)
		proof := p.Proof
		if proof.Check(HashFunc(), lr.RootID, hash) {
			log.Lvl1("Package", name, "correctly verified")
		} else {
			log.ErrFatal(errors.New("The proof for " + name + " is not correct."))
		}
		i = i + 1
		if i > e.NumberOfInstalledPackages {
			break
		}
	}
	round.Record()

	/*
		release, err := updateClient.LatestRelease("Debian-jessie-updates")

		repo := release.Repository
		if repo == nil {
			log.Lvl1("The repository contained in the release is nil")
		}
		root := release.RootID
		if len(root) == 0 {
			log.Lvl1("No root hash, has the Merkle-tree correctly been built ?")
		}

		// build the merkle-tree for packages
		hashes := make([]crypto.HashID, len(repo.Packages))
		for i, p := range repo.Packages {
			hashes[i] = crypto.HashID(p.Hash)
		}
		possibleRoot, _ := crypto.ProofTree(HashFunc(), hashes)
		if !bytes.Equal(possibleRoot, root) {
			log.Lvl1("Wrong root hash")
		}
		for _, p := range release.Repository.Packages {
			for _, proof := range release.Proofs {
				if proof.Check(HashFunc(), release.RootID,
					[]byte(p.Hash)) {
					log.Lvl1("Proof is valid for", p.Name)
				}
			}
			for i, installed_p := range installed_packages {
				if p.Name == installed_p {
					log.Lvl1("Checking updates for", p.Name)
					if p.Hash != installed_packages_hashes[i] {
						log.Lvl1(p.Name, "needs to be updated, updating it now.")
					}
				}
			}

		}
	*/

	// Get the latest repo Skipchain element
	/*repoSCret, err := service.RepositorySC(nil, &RepositorySC{"stable-update"})
	log.ErrFatal(err)
	sc := repoSCret.(*RepositorySCRet).Last
	log.Lvl2("latest block hash : ", sc.Hash)

	// From now on all the packages are in the Skipchain and ready to receive
	// requests by the clients.

	//timeClient := timestamp.NewClient()
	*/
	return nil
}
