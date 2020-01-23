package main

import (
	"github.com/eltaline/badgerhold"
	"os"
	"time"
)

// Compaction Scheduler

func CompactScheduler(cdb *badgerhold.Store) {
	defer wg.Done()

	// Wait Group

	wg.Add(1)

	// Variables

	opentries := 30
	timeout := time.Duration(60) * time.Second

	// Struct

	type Paths struct {
		Path string
	}

	// Loggers

	appLogger, applogfile := AppLogger()
	defer applogfile.Close()

	for {

		// Shutdown

		if shutdown {
			wshutdown = true
			break
		}

		past := time.Now().Add(time.Duration(-24*cmptime) * time.Hour)

		var dataSlice []Compact = nil
		var pathsSlice []Paths = nil
		var paths Paths

		err := cdb.Find(&dataSlice, badgerhold.Where("Time").Lt(past).And("MachID").Eq(machid))
		if err != nil {
			appLogger.Errorf("| Find compactions paths error | %v", err)
			time.Sleep(cmpcheck)
			continue
		}

		for _, scan := range dataSlice {
			paths.Path = scan.Path
			pathsSlice = append(pathsSlice, paths)
		}

		for _, dbf := range pathsSlice {

			sdts := &Compact{}

			if !FileExists(dbf.Path) {

				appLogger.Errorf("| Can`t open db for compaction error | DB [%s] | %v", dbf.Path, err)
				err = cdb.Delete(dbf.Path, sdts)
				if err != nil {
					appLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
				}

				continue

			}

			infile, err := os.Stat(dbf.Path)
			if err != nil {

				appLogger.Errorf("| Can`t stat file error | File [%s] | %v", dbf.Path, err)
				err = cdb.Delete(dbf.Path, sdts)
				if err != nil {
					appLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
				}

				continue

			}

			filemode := infile.Mode()

			db, err := BoltOpenWrite(dbf.Path, filemode, timeout, opentries, freelist)
			if err != nil {

				appLogger.Errorf("| Can`t open db for compaction error | DB [%s] | %v", dbf.Path, err)
				err = cdb.Delete(dbf.Path, sdts)
				if err != nil {
					appLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
				}

				continue

			}
			defer db.Close()

			err = db.CompactQuietly()
			if err != nil {
				appLogger.Errorf("| Scheduled compaction task error | DB [%s] | %v", dbf.Path, err)
				db.Close()

				err = cdb.Delete(dbf.Path, sdts)
				if err != nil {
					appLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
				}

				continue

			}

			err = os.Chmod(dbf.Path, filemode)
			if err != nil {
				appLogger.Errorf("Can`t chmod db error | DB [%s] | %v", dbf.Path, err)
				db.Close()

				err = cdb.Delete(dbf.Path, sdts)
				if err != nil {
					appLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
				}

				continue

			}

			err = cdb.Delete(dbf.Path, sdts)
			if err != nil {
				appLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
				db.Close()
				continue
			}

			db.Close()

		}

		time.Sleep(cmpcheck)

	}

}
