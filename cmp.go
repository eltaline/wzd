/*

Copyright © 2020 Andrey Kuvshinov. Contacts: <syslinux@protonmail.com>
Copyright © 2020 Eltaline OU. Contacts: <eltaline.ou@gmail.com>
All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The wZD project contains unmodified/modified libraries imports too with
separate copyright notices and license terms. Your use of the source code
this libraries is subject to the terms and conditions of licenses these libraries.

*/

package main

import (
	"bytes"
	"encoding/gob"
	"github.com/eltaline/mmutex"
	"github.com/eltaline/nutsdb"
	"os"
	"time"
)

// CMPScheduler : Compaction/Defragmentation scheduler
func CMPScheduler(keymutex *mmutex.Mutex, cdb *nutsdb.DB) {

	// Variables

	opentries := 30
	trytimes := 30
	timeout := time.Duration(60) * time.Second

	// Struct

	type Paths struct {
		Key  []byte
		Path string
	}

	var rpth []Paths
	var r Paths

	// Loggers

	appLogger, applogfile := AppLogger()
	defer applogfile.Close()

	// Shutdown

	if shutdown {
		return
	}

	past := time.Now().Add(time.Duration(-24*cmptime) * time.Hour)

	cerr := cdb.View(func(tx *nutsdb.Tx) error {

		var err error

		var entries nutsdb.Entries

		entries, err = tx.GetAll(cmpbucket)

		if entries == nil {
			return nil
		}

		if err != nil {
			return err
		}

		for _, entry := range entries {

			if shutdown {
				break
			}

			var ev Compact

			dec := gob.NewDecoder(bytes.NewReader(entry.Value))
			err := dec.Decode(&ev)
			if err != nil {

				appLogger.Errorf("| Gob decode from compaction db error | %v", err)

				r.Key = entry.Key
				r.Path = ev.Path

				rpth = append(rpth, r)

				continue

			}

			diff := ev.Time.Sub(past)

			if diff < 0 {

				r.Key = entry.Key
				r.Path = ev.Path

				rpth = append(rpth, r)

			}

		}

		return nil

	})

	if cerr != nil {
		appLogger.Errorf("| Work with compaction db error | %v", cerr)
	}

	for _, dbf := range rpth {

		if shutdown {
			break
		}

		var err error

		key := false

		sdbf := string(dbf.Key)

		for i := 0; i < trytimes; i++ {

			if key = keymutex.TryLock(dbf.Path); key {
				break
			}

			time.Sleep(defsleep)

		}

		if key {

			if !FileExists(dbf.Path) {

				appLogger.Errorf("| Can`t open db for compaction error | DB [%s] | %v", dbf.Path, err)
				err = NDBDelete(cdb, cmpbucket, dbf.Key)
				if err != nil {
					appLogger.Errorf("| Delete compaction task error | DB Key [%s] | %v", sdbf, err)
				}

				keymutex.Unlock(dbf.Path)
				continue

			}

			infile, err := os.Stat(dbf.Path)
			if err != nil {

				appLogger.Errorf("| Can`t stat file error | File [%s] | %v", dbf.Path, err)
				err = NDBDelete(cdb, cmpbucket, dbf.Key)
				if err != nil {
					appLogger.Errorf("| Delete compaction task error | DB Key [%s] | %v", sdbf, err)
				}

				keymutex.Unlock(dbf.Path)
				continue

			}

			filemode := infile.Mode()

			db, err := BoltOpenWrite(dbf.Path, filemode, timeout, opentries, freelist)
			if err != nil {

				appLogger.Errorf("| Can`t open db for compaction error | DB [%s] | %v", dbf.Path, err)
				err = NDBDelete(cdb, cmpbucket, dbf.Key)
				if err != nil {
					appLogger.Errorf("| Delete compaction task error | DB Key [%s] | %v", sdbf, err)
				}

				keymutex.Unlock(dbf.Path)
				continue

			}

			err = db.CompactQuietly()
			if err != nil {
				appLogger.Errorf("| Scheduled compaction task error | DB [%s] | %v", dbf.Path, err)

				err = NDBDelete(cdb, cmpbucket, dbf.Key)
				if err != nil {
					appLogger.Errorf("| Delete compaction task error | DB Key [%s] | %v", sdbf, err)
				}

				db.Close()
				keymutex.Unlock(dbf.Path)
				continue

			}

			err = os.Chmod(dbf.Path, filemode)
			if err != nil {
				appLogger.Errorf("Can`t chmod db error | DB [%s] | %v", dbf.Path, err)

				err = NDBDelete(cdb, cmpbucket, dbf.Key)
				if err != nil {
					appLogger.Errorf("| Delete compaction task error | DB Key [%s] | %v", sdbf, err)
				}

				db.Close()
				keymutex.Unlock(dbf.Path)
				continue

			}

			err = NDBDelete(cdb, cmpbucket, dbf.Key)
			if err != nil {
				appLogger.Errorf("| Delete compaction task error | DB Key [%s] | %v", sdbf, err)
				db.Close()
				keymutex.Unlock(dbf.Path)
				continue
			}

			db.Close()
			keymutex.Unlock(dbf.Path)

		} else {

			appLogger.Errorf("| Timeout mmutex lock error | DB [%s]", dbf.Path)
			continue
		}

	}

}
