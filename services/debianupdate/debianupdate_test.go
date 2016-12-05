package debianupdate

import (
	"flag"
	"os"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/monitor"
	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/sda"
	"github.com/stretchr/testify/assert"
)

func init() {
	initGlobals(3)
}

func TestMain(m *testing.M) {
	os.RemoveAll("config")
	rc := map[string]string{}
	mon := monitor.NewMonitor(monitor.NewStats(rc))
	go func() { log.ErrFatal(mon.Listen()) }()
	local := "localhost:" + strconv.Itoa(monitor.DefaultSinkPort)
	log.ErrFatal(monitor.ConnectSink(local))

	flag.Parse()
	log.TestOutput(testing.Verbose(), 2)
	done := make(chan int)
	go func() {
		code := m.Run()
		done <- code
	}()
	select {
	case code := <-done:
		monitor.EndAndCleanup()
		log.AfterTest(nil)
		os.Exit(code)
	case <-time.After(log.MainTestWait):
		log.Error("Didn't finish in time")
		pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
		os.Exit(1)
	}
}

func TestDebianUpdate_CreateRepository(t *testing.T) {
	local := sda.NewLocalTest()
	defer local.CloseAll()
	_, roster, s := local.MakeHELS(5, debianUpdateService)
	service := s.(*DebianUpdate)
	release1 := chain1.blocks[0].release
	repo1 := chain1.blocks[0].repo
	sigs2 := chain2.blocks[1].sigs
	// This should fail as the signatures are wrong
	createRepo, err := service.CreateRepository(nil,
		&CreateRepository{
			Roster:  roster,
			Release: &Release{repo1, sigs2},
			Base:    2,
			Height:  10,
		})
	assert.NotNil(t, err, "Accepted wrong signatures")
	createRepo, err = service.CreateRepository(nil,
		&CreateRepository{roster, release1, 2, 10})
	log.ErrFatal(err)

	repoChain := createRepo.(*CreateRepositoryRet).RepositoryChain
	assert.NotNil(t, repoChain.Data)
	repo := repoChain.Release.Repository
	assert.Equal(t, *repo1, *repo)
	assert.Equal(t, *repo1,
		*service.Storage.RepositoryChain[repo.GetName()].Release.Repository)
}

// repositoryChain tracks all test releases for one fake repo
type repositoryChain struct {
	repo   string
	blocks []*repositoryBlock
}

// packageBlock tracks all information on one release of a package
type repositoryBlock struct {
	keys       []*PGP
	keysPublic []string
	repo       *Repository
	release    *Release
	sigs       []string
}

var chain1 *repositoryChain
var chain2 *repositoryChain

var keys []*PGP
var keysPublic []string

func initGlobals(nbrKeys int) {
	for i := 0; i < nbrKeys; i++ {
		keys = append(keys, NewPGP())
		keysPublic = append(keysPublic, keys[i].ArmorPublic())
	}

	createBlock := func(origin, suite, version string) *repositoryBlock {
		packages := []*Package{
			{"test1", "0.1", "0000", false},
			{"test2", "0.1", "0101", false},
			{"test3", "0.1", "1010", false},
			{"test4", "0.1", "1111", false},
		}
		repo1 := &Repository{
			Origin:    origin,
			Suite:     suite,
			Version:   version,
			Keys:      keysPublic,
			Threshold: 3,
			Packages:  packages,
			SourceUrl: "http://mirror.switch.ch/ftp/mirror/debian/dists/stable/main/binary-amd64/",
		}
		p1, err := network.MarshalRegisteredType(repo1)
		log.ErrFatal(err)
		var sigs1 []string
		for _, k := range keys {
			s1, err := k.Sign(p1)
			log.ErrFatal(err)
			sigs1 = append(sigs1, s1)
		}
		return &repositoryBlock{
			keys:       keys,
			keysPublic: keysPublic,
			repo:       repo1,
			release:    &Release{repo1, sigs1},
			sigs:       sigs1,
		}
	}

	createChain := func(origin string, suite string) *repositoryChain {
		b1 := createBlock(origin, suite, "1.2")
		b2 := createBlock(origin, suite, "1.3")
		return &repositoryChain{
			repo:   origin + "-" + suite,
			blocks: []*repositoryBlock{b1, b2},
		}
	}

	chain1 = createChain("debian", "stable")
	chain2 = createChain("debian", "stable-update")
}
