package main

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/eltaline/bolt"
	"github.com/eltaline/mmutex"
	"github.com/eltaline/nutsdb"
	"github.com/kataras/iris"
	"hash/crc64"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Delete

// ZDDel : DELETE method
func ZDDel(keymutex *mmutex.Mutex, cdb *nutsdb.DB, ndb *nutsdb.DB, wg *sync.WaitGroup) iris.Handler {
	return func(ctx iris.Context) {
		defer wg.Done()

		var err error

		// Wait Group

		wg.Add(1)

		// Loggers

		delLogger, dellogfile := DelLogger()
		defer dellogfile.Close()

		// Vhost / IP Client

		ip := ctx.RemoteAddr()
		cip := net.ParseIP(ip)
		vhost := strings.Split(ctx.Host(), ":")[0]

		// Shutdown

		if shutdown {
			ctx.StatusCode(iris.StatusInternalServerError)
			// _, err = ctx.WriteString("[ERRO] Shutdown wZD server in progress\n")
			// if err != nil {
			//      delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client| %v", vhost, ip, err)
			// }
			return
		}

		uri := ctx.Path()
		params := ctx.URLParams()

		fromfile := ctx.GetHeader("FromFile")
		fromarchive := ctx.GetHeader("FromArchive")

		hcompact := ctx.GetHeader("Compact")

		badhost := true
		badip := true

		fdelete := false

		base := "/notfound"

		compaction := true
		compact := false

		trytimes := 5
		opentries := 5
		locktimeout := 5

		filemode := os.FileMode(0640)

		delbolt := false
		deldir := false

		log4xx := true

		dir := filepath.Dir(uri)
		file := filepath.Base(uri)

		for _, Server := range config.Server {

			if vhost == Server.HOST {

				badhost = false

				base = filepath.Clean(Server.ROOT)

				for _, Vhost := range delallow {

					if vhost == Vhost.Vhost {

						for _, CIDR := range Vhost.CIDR {
							_, ipnet, _ := net.ParseCIDR(CIDR.Addr)
							if ipnet.Contains(cip) {
								badip = false
								break
							}
						}

						break

					}

				}

				fdelete = Server.DELETE

				compaction = Server.COMPACTION

				trytimes = Server.TRYTIMES
				opentries = Server.OPENTRIES
				locktimeout = Server.LOCKTIMEOUT

				cfilemode, err := strconv.ParseUint(fmt.Sprintf("%d", Server.FILEMODE), 8, 32)
				switch {
				case err != nil || cfilemode == 0:
					filemode = os.FileMode(0640)
				default:
					filemode = os.FileMode(cfilemode)
				}

				delbolt = Server.DELBOLT
				deldir = Server.DELDIR

				log4xx = Server.LOG4XX

				break

			}

		}

		if badhost {

			ctx.StatusCode(iris.StatusMisdirectedRequest)

			if log4xx {
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 421 | Not found configured virtual host", vhost, ip)
			}

			if debugmode {

				_, err = ctx.Writef("[ERRO] Not found configured virtual host | Virtual Host [%s]\n", vhost)
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if badip {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Forbidden", vhost, ip)
			}

			if debugmode {

				_, err = ctx.Writef("[ERRO] Not found allowed ip | Virtual Host [%s]\n", vhost)
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if !fdelete {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Delete disabled", vhost, ip)
			}

			if debugmode {

				_, err = ctx.Writef("[ERRO] Delete disabled | Virtual Host [%s]\n", vhost)
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if len(params) != 0 {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The query arguments is not allowed during DELETE request", vhost, ip)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] The query arguments is not allowed during DELETE request\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		mchregcrcbolt := rgxcrcbolt.MatchString(file)

		if !delbolt {

			mchregbolt := rgxbolt.MatchString(file)

			if mchregbolt {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Delete bolt request is not allowed during DELETE request", vhost, ip)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Delete bolt request is not allowed during DELETE request\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

		}

		if mchregcrcbolt {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Restricted to delete .crcbolt file error | File [%s]", vhost, ip, file)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Restricted to delete .crcbolt file error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

		}

		if hcompact != "" {

			compact64, err := strconv.ParseUint(hcompact, 10, 8)
			if err != nil {

				ctx.StatusCode(iris.StatusBadRequest)

				if log4xx {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Compact uint error during DELETE request | Compact [%s] | %v", vhost, ip, hcompact, err)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Compact uint error during DELETE request\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if compact64 >= 1 {
				compact = true
			}

		}

		abs := filepath.Clean(base + dir + "/" + file)
		ddir := filepath.Clean(base + dir)

		dbn := filepath.Base(dir)
		dbf := filepath.Clean(base + dir + "/" + dbn + ".bolt")

		bucket := ""
		ibucket := "index"
		sbucket := "size"
		tbucket := "time"

		timeout := time.Duration(locktimeout) * time.Second

		if file == "/" {

			ctx.StatusCode(iris.StatusBadRequest)

			if log4xx {
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | No given file name error | File [%s]", vhost, ip, file)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] No given file name error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if !DirExists(ddir) {

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, ddir)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if !FileExists(abs) && !FileExists(dbf) {

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s] | DB [%s]", vhost, ip, abs, dbf)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t find file and archive db error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		key := false

		for i := 0; i < trytimes; i++ {

			if key = keymutex.TryLock(abs); key {
				break
			}

			time.Sleep(defsleep)

		}

		if key {

			if FileExists(abs) && fromarchive != "1" {
				err = RemoveFile(abs, ddir, deldir)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t remove file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t remove file error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				if search {

					dcrc := crc64.Checksum([]byte(ddir), ctbl64)
					nbucket := strconv.FormatUint(dcrc, 16)

					nkey := []byte("f:" + file)

					err = NDBDelete(ndb, nbucket, nkey)
					if err != nil {
						delLogger.Errorf("| Delete file from search db error | File [%s] | Path [%s] | Bucket [%s] | %v", file, abs, nbucket, err)
					}

					if deldir {

						ed, _ := IsEmptyDir(ddir)

						if ed {

							radix.Lock()
							tree, _, _ = tree.Delete([]byte(ddir))
							radix.Unlock()

							dcrc = crc64.Checksum([]byte(filepath.Dir(ddir)), ctbl64)
							nbucket = strconv.FormatUint(dcrc, 16)

							nkey = []byte("d:" + dbn)

							err = NDBDelete(ndb, nbucket, nkey)
							if err != nil {
								delLogger.Errorf("| Delete directory from search db error | Directory [%s] | Bucket [%s] | %v", dbn, nbucket, err)
							}

							// Add delete bucket function to NutsDB

						}

					}

				}

				keymutex.Unlock(abs)
				return

			}

			keymutex.Unlock(abs)

			if fromfile == "1" {

				ctx.StatusCode(iris.StatusNotFound)

				if log4xx {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | File [%s] | Path [%s]", vhost, ip, file, abs)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find file error\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

			}

		} else {

			ctx.StatusCode(iris.StatusServiceUnavailable)
			delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 503 | Timeout mmutex lock error | File [%s] | DB [%s]", vhost, ip, file, dbf)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Timeout mmutex lock error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		var keyexists string = ""

		var bf BoltFiles
		var bfiles []BoltFiles

		var dcount int64 = 0

		if FileExists(dbf) {

			bf.Name = dbf
			bfiles = append(bfiles, bf)

		}

		for {

			dcount++
			ndbf := fmt.Sprintf("%s/%s_%08d.bolt", ddir, dbn, dcount)

			if FileExists(ndbf) {

				bf.Name = ndbf
				bfiles = append(bfiles, bf)

			} else {
				break
			}

		}

		for _, bfile := range bfiles {

			dbf = bfile.Name

			lnfile, err := os.Lstat(dbf)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t lstat db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t lstat db file error\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if lnfile.Mode()&os.ModeType != 0 {

				ctx.StatusCode(iris.StatusInternalServerError)
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Non-regular db file error | File [%s] | DB [%s]", vhost, ip, file, dbf)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Non-regular db file error\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			db, err := BoltOpenRead(dbf, filemode, timeout, opentries, freelist)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			keyexists, err = KeyExists(db, ibucket, file)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t check key of file in index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t check key of file in index db bucket error\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				return

			}

			if keyexists != "" {
				db.Close()
				break
			}

			db.Close()

		}

		if keyexists == "" {

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t find file in archive db error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		bucket = keyexists

		key = false

		for i := 0; i < trytimes; i++ {

			if key = keymutex.TryLock(dbf); key {
				break
			}

			time.Sleep(defsleep)

		}

		if key {

			db, err := BoltOpenWrite(dbf, filemode, timeout, opentries, freelist)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				keymutex.Unlock(dbf)
				return

			}
			defer db.Close()

			sizeexists, err := KeyExists(db, sbucket, file)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t check key of file in size db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t check key of file in size db bucket error\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				keymutex.Unlock(dbf)
				return

			}

			timeexists, err := KeyExists(db, tbucket, file)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t check key of file in time db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t check key of file in time db bucket error\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				keymutex.Unlock(dbf)
				return

			}

			if keyexists != "" || sizeexists != "" || timeexists != "" {

				err = db.Update(func(tx *bolt.Tx) error {

					verr := errors.New("bucket not exists")

					b := tx.Bucket([]byte(bucket))
					if b != nil {
						err = b.Delete([]byte(file))
						if err != nil {
							return err
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t remove file from db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t remove file from db bucket error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				err = db.Update(func(tx *bolt.Tx) error {

					verr := errors.New("index bucket not exists")

					b := tx.Bucket([]byte(ibucket))
					if b != nil {
						err = b.Delete([]byte(file))
						if err != nil {
							return err
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t remove key from index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t remove key from index db bucket error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				err = db.Update(func(tx *bolt.Tx) error {

					verr := errors.New("size bucket not exists")

					b := tx.Bucket([]byte(sbucket))
					if b != nil {
						err = b.Delete([]byte(file))
						if err != nil {
							return err
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t remove key from size db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t remove key from size db bucket error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				err = db.Update(func(tx *bolt.Tx) error {

					verr := errors.New("time bucket not exists")

					b := tx.Bucket([]byte(tbucket))
					if b != nil {
						err = b.Delete([]byte(file))
						if err != nil {
							return err
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t remove key from time db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t remove key from time db bucket error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if search {

					dcrc := crc64.Checksum([]byte(ddir), ctbl64)
					nbucket := strconv.FormatUint(dcrc, 16)

					nkey := []byte("b:" + file)

					err = NDBDelete(ndb, nbucket, nkey)
					if err != nil {
						delLogger.Errorf("| Delete file from search db error | File [%s] | DB [%s] | Bucket [%s] | %v", file, dbf, nbucket, err)
					}

				}

				keyscountbucket, err := KeysCountBucket(db, bucket)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count keys of files in current db bucket error | DB [%s] | %v", vhost, ip, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count keys of files in current db bucket error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if keyscountbucket == 0 {

					err = db.Update(func(tx *bolt.Tx) error {
						err = tx.DeleteBucket([]byte(bucket))
						if err != nil {
							return err
						}
						return nil

					})
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t delete current db bucket error | DB [%s] | %v", vhost, ip, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t delete current db bucket error\n")
							if err != nil {
								delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				}

				keyscount, err := KeysCount(db, ibucket)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count keys of files in index db bucket error | DB [%s] | %v", vhost, ip, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count keys of files in index db bucket error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if keyscount == 0 {

					err = RemoveFileDB(dbf, ddir, deldir)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t remove db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t remove db file error\n")
							if err != nil {
								delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					if search && deldir {

						ed, _ := IsEmptyDir(ddir)

						if ed {

							radix.Lock()
							tree, _, _ = tree.Delete([]byte(ddir))
							radix.Unlock()

							dcrc := crc64.Checksum([]byte(filepath.Dir(ddir)), ctbl64)
							nbucket := strconv.FormatUint(dcrc, 16)

							nkey := []byte("d:" + dbn)

							err = NDBDelete(ndb, nbucket, nkey)
							if err != nil {
								delLogger.Errorf("| Delete directory from search db error | Directory [%s] | Bucket [%s] | %v", dbn, nbucket, err)
							}

							// Add delete bucket function to NutsDB

						}

					}

					if compaction && cmpsched {

						bdbf := make([]byte, 8)
						Endian.PutUint64(bdbf, crc64.Checksum([]byte(dbf), ctbl64))

						err = NDBDelete(cdb, cmpbucket, bdbf)
						if err != nil {
							delLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if compaction && cmpsched || compact {

					if compact {

						err = db.CompactQuietly()
						if err != nil {
							delLogger.Errorf("| On the fly compaction error | DB [%s] | %v", dbf, err)
						}

						err = os.Chmod(dbf, filemode)
						if err != nil {
							delLogger.Errorf("Can`t chmod db error | DB [%s] | %v", dbf, err)
						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					bdbf := make([]byte, 8)
					Endian.PutUint64(bdbf, crc64.Checksum([]byte(dbf), ctbl64))

					bval := new(bytes.Buffer)

					sdts := &Compact{
						Path: dbf,
						Time: time.Now(),
					}

					enc := gob.NewEncoder(bval)
					err := enc.Encode(sdts)
					if err != nil {

						delLogger.Errorf("| Gob encode for compaction db error | Path [%s] | %v", dbf, err)

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					err = NDBInsert(cdb, cmpbucket, bdbf, bval.Bytes(), 0)
					if err != nil {

						delLogger.Errorf("| Insert/Update data error | Path [%s] | %v", dbf, err)
						delLogger.Errorf("| Compaction will be started on the fly | DB [%s]", dbf)

						err = db.CompactQuietly()
						if err != nil {
							delLogger.Errorf("| On the fly compaction error | DB [%s] | %v", dbf, err)
						}

						err = os.Chmod(dbf, filemode)
						if err != nil {
							delLogger.Errorf("Can`t chmod db error | DB [%s] | %v", dbf, err)
						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				}

				db.Close()
				keymutex.Unlock(dbf)
				return

			}

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | File [%s] | DB [%s]", vhost, ip, file, dbf)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t find file in archive db error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			db.Close()
			keymutex.Unlock(dbf)
			return

		} else {

			ctx.StatusCode(iris.StatusServiceUnavailable)
			delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 503 | Timeout mmutex lock error | File [%s] | DB [%s]", vhost, ip, file, dbf)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Timeout mmutex lock error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

	}

}
