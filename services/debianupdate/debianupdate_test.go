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
	//"github.com/stretchr/testify/assert"
	//"github.com/stretchr/testify/require"
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
		packages := []*Package{}
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
			repo:   origin + " " + suite,
			blocks: []*repositoryBlock{b1, b2},
		}
	}

	chain1 = createChain("debian", "test1")
	chain2 = createChain("debian", "test2")
}

/*
import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dedis/cothority/crypto"
	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/monitor"
	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/sda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestNewDebianUpdate(t *testing.T) {
	require := require.New(t)
	local := sda.NewLocalTest()
	_, _, s := local.MakeHELS(5, debianUpdateService)
	require.NotNil(s)
	defer local.CloseAll()
	service := s.(*DebianUpdate)
	require.NotNil(service)
}

func TestNewPackage(t *testing.T) {
	require := require.New(t)

	pkg := Package{
		Name:         "0ad",
		Version:      "0.1",
		BinaryHash:   "01234",
		Reproducible: false,
	}

	require.Equal("0ad", pkg.Name)
	require.Equal("0.1", pkg.Version)
	require.Equal("01234", pkg.BinaryHash)
	require.Equal(false, pkg.Reproducible)
}

func TestNewRepository(t *testing.T) {
	require := require.New(t)

	pkg1 := Package{"pkg1", "0.1", "01234", true}
	pkg2 := Package{"pkg2", "0.5", "0123511512", false}
	repo := Repository{
		Name:     "stable",
		URL:      "http://mirror.switch.ch/deb",
		Key:      "aoksdok1ok2o3k1o2k3aoskd",
		Packages: []Package{pkg1, pkg2},
	}

	require.NotNil(repo.Packages[0])
}

func TestNewRelease(t *testing.T) {
	require := require.New(t)

	pkg1 := Package{"pkg1", "0.1", "01234", true}
	pkg2 := Package{"pkg2", "0.5", "0123511512", false}
	pkg3 := Package{"pkg3", "0.3", "01234", true}
	pkg4 := Package{"pkg4", "0.4", "0123511512", false}
	repo := Repository{"stable", "url", "aoksdok1ok2o3k1o2k3aoskd",
		[]Package{pkg1, pkg2, pkg3, pkg4}}

	release := Release{
		Name:       "Jessie",
		Version:    "8.1",
		Date:       time.Now(),
		Repository: repo,
	}

	require.NotNil(release)
}

func TestService_CreateRelease(t *testing.T) {
	local := sda.NewLocalTest()
	defer local.CloseAll()
	_, roster, s := local.MakeHELS(5, debianUpdateService)
	service := s.(*DebianUpdate)
	pkg1 := Package{"0ad", "0.0.17-1", "d850ad98b399016b3456dd516d2e114fd72c956aa7b5ddaa0858f792bb005c5e", false}
	pkg2 := Package{"2048-qt", "0.1.5-2", "da02c7ea81f417a916f51f39d9c641912cf8de9dce5cfe88d3fec4d5f32f1df2", false}

	repo := Repository{"stable/main/binary-amd64", "http://mirror.switch.ch/ftp/mirror/debian/dists/stable/main/binary-amd64/Packages.gz", "pgp", []Package{pkg1, pkg2}}

	release := &Release{"Jessie", "8.6", time.Now(), repo, []string{"blbl", "pgp"}}

	_, err := network.MarshalRegisteredType(release)
	log.ErrFatal(err)

	crr, err := service.CreateRelease(nil, &CreateRelease{roster, release, 2, 10})
	assert.NotNil(t, err, "Accepted wrong signature")

	crr, err = service.CreateRelease(nil, &CreateRelease{roster, release, 2, 10})
	log.ErrFatal(err)

	rc := crr.(*CreateReleaseRet).ReleaseChain
	assert.NotNil(t, rc.Data)
}

func TestReadReleaseFromFile(t *testing.T) {
	require := require.New(t)

	filename := "Packages.gz"
	gz, err := os.Open(filename)

	log.ErrFatal(err)
	defer gz.Close()

	file, err := gzip.NewReader(gz)

	log.ErrFatal(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	package_name := ""
	package_hash := ""

	block := []string{}
	hashes := []crypto.HashID{}
	names := []string{}

	for scanner.Scan() {
		line := scanner.Text()

		if len(strings.TrimSpace(line)) != 0 {
			block = append(block, line)
			continue
		}

		if len(block) != 0 {
			package_name, package_hash = ExtractNameAndHash(block)
			hashes = append(hashes, []byte(package_hash))
			names = append(names, package_name)
			block = []string{}
		}
	}

	log.Lvl2("Building the Merkle tree for the repository package list")
	root := CreateMerkleTree(names, hashes)
	log.Lvl2("root: ", hex.EncodeToString(root))

	require.NotNil(root)
}

func ExtractNameAndHash(block []string) (string, string) {
	name := ""
	hash := ""

	if strings.Contains(block[0], "Package:") {
		name = strings.Replace(block[0], "Package: ", "", 1)
	}

	index := -1
	// find index of the last file's hash
	for i, l := range block {
		// the index has been set and the first char of a line is no longer a space
		if index != -1 && l[0] != ' ' {
			hash = strings.Split(block[i-1], " ")[1]
			break
		}

		if strings.Contains(l, "Checksums-Sha256:") {
			index = i
		}
	}

	return name, hash
}

func CreateMerkleTree(names []string, hashes []crypto.HashID) crypto.HashID {
	root, _ := crypto.ProofTree(sha256.New, hashes)
	return root
}*/

/*func TestNewDebianRelease(t *testing.T) {
	require := require.New(t)
	dr, err := NewDebianRelease("", "", 3)
	require.NotNil(err)

	dr, err = NewDebianRelease("19700101000000,ls,0.01,hash1,hash2", "", 3)
	log.ErrFatal(err)
	require.Equal("19700101000000", dr.Snapshot)
	require.Equal("ls", dr.Policy.Name)
	require.Equal("0.01", dr.Policy.Version)
}

func TestGetReleases(t *testing.T) {
	require := require.New(t)
	dr, err := GetReleases("doesntexist")
	require.NotNil(err)
	dr, err = GetReleases("snapshot/updates.csv")
	log.ErrFatal(err)
	require.Equal(4, len(dr))
	require.Equal("ls", dr[0].Policy.Name)
	require.Equal("cp", dr[1].Policy.Name)
	require.Equal("0.1", dr[1].Policy.Version)
	for _, d := range dr {
		p := d.Policy
		require.Equal("1234caffee", p.BinaryHash)
		require.Equal("deadbeef", p.SourceHash)
		require.Equal(5, p.Threshold)
		for i, k := range p.Keys {
			pgp := NewPGPPublic(k)
			policyBin, err := network.MarshalRegisteredType(p)
			log.ErrFatal(err)
			log.ErrFatal(pgp.Verify(policyBin, d.Signatures[i]))
		}
	}
}*/
