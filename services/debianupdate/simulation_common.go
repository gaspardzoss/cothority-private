package debianupdate

import (
	"github.com/dedis/cothority/app/lib/config"
	"github.com/dedis/cothority/log"

	"os"
	"path"
	"strings"
)

// CopyFiles copies the files from the service/swupdate-directory
// to the simulation-directory
func CopyFiles(dir, snapshots string, releases string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	log.Lvl2("We're in", wd)
	for _, file := range append(strings.Split(snapshots, " "),
		strings.Split(releases, " ")...) {
		dst := path.Join(dir, path.Base(file))
		if _, err := os.Stat(dst); err != nil {
			err := config.Copy(dst, "../services/debianupdate/script/"+file)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// CopyFiles copies the files from the service/swupdate-directory
// to the simulation-directory
func CopyDir(dir, snapshots string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	log.Lvl2("We're in", wd)
	for _, file := range append(strings.Split(snapshots, " "),
		strings.Split(releases, " ")...) {
		dst := path.Join(dir, path.Base(file))
		if _, err := os.Stat(dst); err != nil {
			err := config.Copy(dst, "../services/debianupdate/script/"+file)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
