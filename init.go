package main

import (
	"bytes"
	"encoding/binary"
	//"encoding/json"
	"errors"
	"fmt"
	"github.com/eltaline/bolt"
	"github.com/eltaline/nutsdb"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SearchInit : Search Metadata Database Initialization
func SearchInit(nopt nutsdb.Options) {

	// Wait Group

	var wgs sync.WaitGroup

	// Variables

	var err error

	type mfiles struct {
		dir string
		crc uint64
		thr int
	}

	var mslice []mfiles
	var m mfiles

	ibucket := "index"
	sbucket := "size"
	tbucket := "time"

	opentries := 30
	timeout := time.Duration(60) * time.Second

	verr := errors.New("index/size/time bucket not exists")
	serr := errors.New("key size/date empty")

	// Loggers

	appLogger, applogfile := AppLogger()
	defer applogfile.Close()

	ndb, err := nutsdb.Open(nopt)
	if err != nil {
		appLogger.Errorf("| Can`t open search db error | DB Directory [%s] | %v", nopt.Dir, err)
		fmt.Printf("Can`t open search db error | DB Directory [%s] | %v\n", nopt.Dir, err)
		os.Exit(1)
	}
	defer ndb.Close()

	root := tree.Root()

	walk := func(bdir []byte, dcrc interface{}) bool {

		rand.Seed(time.Now().UnixNano())

		m.dir = string(bdir)
		m.crc = dcrc.(uint64)
		m.thr = rand.Intn(searchinit-1+1) + 1

		mslice = append(mslice, m)

		return false

	}

	root.Walk(walk)

	for i := 1; i <= searchinit; i++ {

		wgs.Add(1)

		go func(i int) {
			defer wgs.Done()

			var nval RawKeysData

			for _, elm := range mslice {

				if elm.thr != i {
					continue
				}

				dirname := elm.dir
				dcrc := elm.crc

				nbucket := strconv.FormatUint(dcrc, 16)

				files, err := ioutil.ReadDir(dirname)
				if err != nil {
					appLogger.Errorf("| Can`t read directory error | Path [%s] | %v", dirname, err)
					fmt.Printf("Can`t read directory error | Path [%s] | %v\n", dirname, err)
					os.Exit(1)
				}

				for _, file := range files {

					fname := file.Name()
					fmode := file.Mode()

					if !file.IsDir() && file.Mode()&os.ModeType != 0 {
						continue
					}

					var nkey []byte

					size := int64(0)
					date := int64(0)

					bname := rgxbolt.MatchString(fname)
					cname := rgxcrcbolt.MatchString(fname)

					if !bname && !cname {

						size = file.Size()
						date = file.ModTime().Unix()

						nval.Size = uint64(size)
						nval.Date = uint64(date)
						nval.Prnt = uint32(0)
						nval.Buck = uint16(0)
						nval.Type = uint16(0)

						if !file.IsDir() {
							nkey = []byte("f:" + fname)
							nval.Type = uint16(0)
						} else {
							nkey = []byte("d:" + fname)
							nval.Type = uint16(2)
						}

						nbuffer := new(bytes.Buffer)

						err = binary.Write(nbuffer, Endian, nval)
						if err != nil {
							appLogger.Errorf("| Can`t write to binary buffer error | File/Path [%s] | %v", fname, err)
							fmt.Printf("Can`t write to binary buffer error | File/Path [%s] | %v\n", fname, err)
							os.Exit(1)
						}

						//json.NewEncoder(nbuffer).Encode(nval)

						err = ndb.Update(func(tx *nutsdb.Tx) error {

							err := tx.Put(nbucket, nkey, nbuffer.Bytes(), 0)
							if err != nil {
								return err
							}

							return nil

						})

						nbuffer.Reset()

						if err != nil {
							appLogger.Errorf("| Can`t write to search db error | File/Path [%s] | %v", fname, err)
							fmt.Printf("Can`t write to search db error | File/Path [%s] | %v\n", fname, err)
							os.Exit(1)
						}

						continue

					}

					if file.IsDir() || cname {
						continue
					}

					var prnt uint64 = 0

					dbf := filepath.Clean(dirname + "/" + fname)

					if strings.ContainsRune(fname, 95) {

						prnt, err = strconv.ParseUint(strings.Split(strings.TrimSuffix(fname, ".bolt"), "_")[1], 10, 64)
						if err != nil {
							appLogger.Errorf("| Bad db file name error | DB [%s] | %v", dbf, err)
							fmt.Printf("Bad db file name error | DB [%s] | %v\n", dbf, err)
							os.Exit(1)
						}

					}

					db, err := BoltOpenRead(dbf, fmode, timeout, opentries, freelist)
					if err != nil {
						appLogger.Errorf("| Can`t open db file error | DB [%s] | %v", dbf, err)
						fmt.Printf("Can`t open db file error | DB [%s] | %v\n", dbf, err)
						os.Exit(1)
					}

					err = db.View(func(tx *bolt.Tx) error {

						b := tx.Bucket([]byte(ibucket))
						if b != nil {

							pos := b.Cursor()

							for inkey, inval := pos.First(); inkey != nil; inkey, inval = pos.Next() {

								nkey = []byte("b:" + string(inkey))

								nbck, err := strconv.Atoi(strings.TrimPrefix(string(inval), "wzd"))
								if err != nil {
									return err
								}

								ksize, err := KeyGetVal(db, sbucket, inkey)
								if err != nil {
									return err
								}

								kdate, err := KeyGetVal(db, tbucket, inkey)
								if err != nil {
									return err
								}

								if ksize != nil && kdate != nil {

									nval.Size = Endian.Uint64(ksize)
									nval.Date = Endian.Uint64(kdate)
									nval.Prnt = uint32(prnt)
									nval.Buck = uint16(nbck)
									nval.Type = uint16(1)

								} else {
									return serr
								}

								nbuffer := new(bytes.Buffer)

								err = binary.Write(nbuffer, Endian, nval)
								if err != nil {
									return err
								}

								//json.NewEncoder(nbuffer).Encode(nval)

								err = NDBInsert(ndb, nbucket, nkey, nbuffer.Bytes(), 0)
								if err != nil {
									appLogger.Errorf("| Can`t write to search db error | File/Path [%s] | In-Bolt File [%s] | %v", fname, string(inkey), err)
									fmt.Printf("Can`t write to search db error | File/Path [%s] | In-Bolt File [%s] | %v\n", fname, string(inkey), err)
									os.Exit(1)
								}

								nbuffer.Reset()

							}

						} else {
							return verr
						}

						return nil

					})

					if err != nil {
						db.Close()
						appLogger.Errorf("| Can`t do work with db`s error | File [%s] | DB [%s] | Search DB [%s] | %v", fname, dbf, nopt.Dir, err)
						fmt.Printf("Can`t do work with db`s error | File [%s] | DB [%s] | Search DB [%s] | %v\n", fname, dbf, nopt.Dir, err)
						os.Exit(1)
					}

					db.Close()
					continue

				}

			}

		}(i)

	}

	wgs.Wait()

	mslice = nil

}
