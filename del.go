package main

import (
	"errors"
	"fmt"
	"github.com/eltaline/badgerhold"
	"github.com/eltaline/bolt"
	"github.com/eltaline/mmutex"
	"github.com/kataras/iris"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Delete

func ZDDel(keymutex *mmutex.Mutex, cdb *badgerhold.Store) iris.Handler {
	return func(ctx iris.Context) {
		defer wg.Done()

		// Wait Group

		wg.Add(1)

		// Loggers

		delLogger, dellogfile := DelLogger()
		defer dellogfile.Close()

		// Vhost / IP Client

		ip := ctx.RemoteAddr()
		vhost := ctx.Host()

		// Shutdown

		if wshutdown {
			ctx.StatusCode(iris.StatusInternalServerError)
			//_, err := ctx.WriteString("Shutdown wZD server in progress\n")
			//if err != nil {
			//	delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
			//}
			return
		}

		uri := ctx.Path()
		params := ctx.URLParams()

		badhost := true

		delete := false

		base := "/notfound"

		compaction := true

		trytimes := 5
		opentries := 5
		locktimeout := 5

		filemode := os.FileMode(0640)

		delbolt := false
		deldir := false

		for _, Server := range config.Server {

			if vhost == Server.HOST {

				badhost = false

				base = Server.ROOT

				delete = Server.DELETE

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

				break

			}

		}

		if badhost {

			ctx.StatusCode(iris.StatusMisdirectedRequest)
			delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Not found configured virtual host", vhost, ip)

			if debugmode {

				_, err := ctx.Writef("[ERRO] Not found configured virtual host | Virtual Host [%s]\n", vhost)
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if !delete {

			ctx.StatusCode(iris.StatusForbidden)
			delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Delete disabled", vhost, ip)

			if debugmode {

				_, err := ctx.Writef("[ERRO] Delete disabled | Virtual Host [%s]\n", vhost)
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if len(params) != 0 {

			ctx.StatusCode(iris.StatusBadRequest)
			delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The query arguments is not allowed during DELETE request", vhost, ip)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The query arguments is not allowed during DELETE request\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		dir := filepath.Dir(uri)
		file := filepath.Base(uri)

		if !delbolt {

			mchregbolt := rgxbolt.MatchString(file)

			if mchregbolt {

				ctx.StatusCode(iris.StatusForbidden)
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The delete bolt request is not allowed during DELETE request", vhost, ip)

				if debugmode {

					_, err := ctx.WriteString("[ERRO] The delete bolt request is not allowed during DELETE request\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

		}

		abs := fmt.Sprintf("%s%s/%s", base, dir, file)
		ddir := fmt.Sprintf("%s%s", base, dir)

		dbn := filepath.Base(dir)
		dbf := fmt.Sprintf("%s%s/%s.bolt", base, dir, dbn)

		bucket := ""
		ibucket := "index"

		timeout := time.Duration(locktimeout) * time.Second

		if file == "/" {

			ctx.StatusCode(iris.StatusBadRequest)
			delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | No given file name error | File [%s]", vhost, ip, file)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] No given file name error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if !DirExists(ddir) {

			ctx.StatusCode(iris.StatusNotFound)
			delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t find directory error | Directory [%s]", vhost, ip, ddir)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] Can`t find directory error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if !FileExists(abs) && !FileExists(dbf) {
			ctx.StatusCode(iris.StatusNotFound)
			return
		}

		fromarchive := ctx.GetHeader("FromArchive")

		key := false

		for i := 0; i < trytimes; i++ {

			if key = keymutex.TryLock(abs); key {
				break
			}

			time.Sleep(defsleep)

		}

		if key {

			if FileExists(abs) && fromarchive != "1" {
				err := RemoveFile(abs, ddir, deldir)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t remove file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t remove file error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				keymutex.Unlock(abs)
				return

			}

			keymutex.Unlock(abs)

		} else {

			ctx.StatusCode(iris.StatusInternalServerError)
			delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Timeout mmutex lock error | File [%s] | DB [%s]", vhost, ip, file, dbf)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] Timeout mmutex lock error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		key = false

		for i := 0; i < trytimes; i++ {

			if key = keymutex.TryLock(dbf); key {
				break
			}

			time.Sleep(defsleep)

		}

		if key {

			db, err := BoltOpenWrite(dbf, filemode, timeout, opentries)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				keymutex.Unlock(dbf)
				return

			}
			defer db.Close()

			keyexists, err := KeyExists(db, ibucket, file)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t check key of file in index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t check key of file in index db bucket error\n")
					if err != nil {
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				db.Close()
				keymutex.Unlock(dbf)
				return

			}

			if keyexists != "" {

				bucket = keyexists

				err = db.Update(func(tx *bolt.Tx) error {

					b := tx.Bucket([]byte(bucket))
					if b != nil {
						err = b.Delete([]byte(file))
						if err != nil {
							return err
						}

					} else {

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

							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t remove key from index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)
							return err

						}

						return nil

					}

					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t remove file from db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t remove file from db bucket error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t remove key from index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t remove key from index db bucket error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				keycountbucket, err := KeyCountBucket(db, bucket)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t count keys of files in current db bucket error | DB [%s] | %v", vhost, ip, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count keys of files in current db bucket error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if keycountbucket == 0 {

					err = db.Update(func(tx *bolt.Tx) error {
						err = tx.DeleteBucket([]byte(bucket))
						if err != nil {
							return err
						}
						return nil

					})
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t delete current db bucket error | DB [%s] | %v", vhost, ip, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t delete current db bucket error\n")
							if err != nil {
								delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				}

				keycount, err := KeyCount(db, ibucket)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t count keys of files in index db bucket error | DB [%s] | %v", vhost, ip, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count keys of files in index db bucket error\n")
						if err != nil {
							delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if keycount == 0 {

					err := RemoveFileDB(dbf, ddir, deldir)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t remove db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t remove db file error\n")
							if err != nil {
								delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					if compaction && cmpsched {

						sdts := &Compact{}

						err = cdb.Delete(dbf, sdts)
						if err != nil {
							delLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if compaction && cmpsched {

					sdts := &Compact{
						Path:   dbf,
						MachID: machid,
						Time:   time.Now(),
					}

					err = cdb.Upsert(dbf, sdts)
					if err != nil {

						delLogger.Errorf("| Insert/Update data error | PATH [%s] | %v", dbf, err)
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
			delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t find file in db error | File [%s] | DB [%s]", vhost, ip, file, dbf)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t find file in db error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			keymutex.Unlock(dbf)
			return

		} else {

			ctx.StatusCode(iris.StatusInternalServerError)
			delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Timeout mmutex lock error | File [%s] | DB [%s]", vhost, ip, file, dbf)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] Timeout mmutex lock error\n")
				if err != nil {
					delLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

	}

}
