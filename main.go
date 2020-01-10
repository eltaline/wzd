package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/eltaline/bolt"
	"github.com/eltaline/machineid"
	"github.com/eltaline/mmutex"
	"github.com/eltaline/toml"
	_ "github.com/go-sql-driver/mysql"
	"github.com/kataras/golog"
	"github.com/kataras/iris"
	"github.com/kataras/iris/middleware/logger"
	"github.com/kataras/iris/middleware/recover"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"hash/crc32"
	"io"
	"io/ioutil"
	"math/rand"
	"mime"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// Global Configuration

type Config struct {
	Global global
	Server map[string]server
}

type global struct {
	BINDADDR          string
	READTIMEOUT       int
	READHEADERTIMEOUT int
	IDLETIMEOUT       int
	WRITETIMEOUT      int
	REALHEADER        string
	CHARSET           string
	DEBUGMODE         bool
	PIDFILE           string
	LOGDIR            string
	LOGMODE           uint32
	DEFSLEEP          int
	OPENTRIES         int
	DBDRIVER          string
	DBFILE            string
	DBHOST            string
	DBPORT            int
	DBNAME            string
	DBUSER            string
	DBPASS            string
	DBCONN            int
	CMPSCHED          bool
	CMPTIME           int
	CMPCOUNT          int
	CMPCHECK          int
}

type server struct {
	HOST           string
	ROOT           string
	UPLOAD         bool
	DELETE         bool
	COMPACTION     bool
	GETBOLT        bool
	GETCOUNT       bool
	GETKEYS        bool
	NONUNIQUE      bool
	WRITEINTEGRITY bool
	READINTEGRITY  bool
	TRYTIMES       int
	LOCKTIMEOUT    int
	ARGS           bool
	CCTRL          int
	FMAXSIZE       int64
	MINBUFFER      int64
	LOWBUFFER      int64
	MEDBUFFER      int64
	BIGBUFFER      int64
	FILEMODE       uint32
	DIRMODE        uint32
	DELBOLT        bool
	DELDIR         bool
}

type header struct {
	Size uint64
	Date uint32
	Mode uint16
	Uuid uint16
	Guid uint16
	Comp uint8
	Encr uint8
	Crcs uint32
	Rsvr uint64
}

type reqRange struct {
	start  int64
	length int64
}

// Global Variables

var (
	Endian binary.ByteOrder

	Uid int64
	Gid int64

	config     Config
	configfile string = "/etc/wzd/wzd.conf"
	wg         sync.WaitGroup

	readtimeout       time.Duration = 60 * time.Second
	readheadertimeout time.Duration = 5 * time.Second
	idletimeout       time.Duration = 60 * time.Second
	writetimeout      time.Duration = 60 * time.Second

	machid string = "nomachineid"

	shutdown  bool = false
	wshutdown bool = false

	debugmode bool = false

	pidfile string = "/run/wzd/wzd.pid"

	logdir  string = "/var/log/wzd"
	logmode os.FileMode

	defsleep  time.Duration = 1 * time.Second
	opentries int           = 30

	dbdriver        = "sqlite"
	dbfile          = "/var/lib/wzd/wzd.sqlite3"
	dbhost   string = "127.0.0.1"
	dbport   int    = 5432
	dbname   string = "wzd"
	dbuser   string = "wzd"
	dbpass   string = "wzd"
	dbconn   int    = 8

	cmpsched bool = true

	cmptime  int           = 30
	cmpcount int           = 100
	cmpcheck time.Duration = 5 * time.Second

	rgxbolt  = regexp.MustCompile(`(\.bolt$)`)
	rgxctype = regexp.MustCompile("(multipart)")
)

// Compaction Scheduler

func compactScheduler(cdb *sql.DB) {
	defer wg.Done()

	// Wait Group

	wg.Add(1)

	// Loggers

	AppLogger, applogfile := appLogger()
	defer applogfile.Close()

	var waiting string

	timeout := time.Duration(60) * time.Second

	type Paths struct {
		Path string
	}

	var paths Paths

	rcmptime := rand.Intn(3 * cmptime)

	switch dbdriver {
	case "sqlite":
		waiting = fmt.Sprintf("SELECT path FROM compact WHERE time <= date('now', '-%d day') AND machid = '%s' OR time <= date('now', '-%d day') OR count >= %d AND machid = '%s';", cmptime, machid, rcmptime, cmpcount, machid)
	case "pgsql":
		waiting = fmt.Sprintf("SELECT path FROM compact WHERE time <= NOW() - INTERVAL '%d days' AND machid = '%s' OR time <= NOW() - INTERVAL '%d days' OR count >= %d AND machid = '%s';", cmptime, machid, rcmptime, cmpcount, machid)
	case "mysql":
		waiting = fmt.Sprintf("SELECT path FROM compact WHERE time <= NOW() - INTERVAL %d DAY AND machid = '%s' OR time <= NOW() - INTERVAL %d DAY OR count >= %d AND machid = '%s';", cmptime, machid, rcmptime, cmpcount, machid)
	default:
		waiting = fmt.Sprintf("SELECT path FROM compact WHERE time <= date('now', '-%d day') AND machid = '%s' OR time <= date('now', '-%d day') OR count >= %d AND machid = '%s';", cmptime, machid, rcmptime, cmpcount, machid)
	}

	for {

		// Shutdown

		if shutdown {
			wshutdown = true
			break
		}

		var pathsSlice []Paths = nil

		rows, err := cdb.Query(waiting)
		if err != nil {
			AppLogger.Errorf("| Select compactions paths with rows query from SQL error | %v", err)
			time.Sleep(cmpcheck)
			continue
		}
		defer rows.Close()

		err = rows.Err()
		if err != nil {
			time.Sleep(cmpcheck)
			continue
		}

		for rows.Next() {

			err = rows.Scan(&paths.Path)
			if err != nil {
				AppLogger.Errorf("| Select compactions paths with rows scan from SQL error | %v", err)
				break
			}

			pathsSlice = append(pathsSlice, paths)

		}

		err = rows.Err()
		if err != nil {
			time.Sleep(cmpcheck)
			continue
		}
		rows.Close()

		for _, dbf := range pathsSlice {

			if !fileExists(dbf.Path) {
				AppLogger.Errorf("| Can`t open db for compaction error | DB [%s] | %v", dbf.Path, err)
				deltask := fmt.Sprintf("DELETE FROM compact WHERE path = '%s';", dbf.Path)
				_, err := cdb.Exec(deltask)
				if err != nil {
					AppLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
					continue
				}
				continue

			}

			infile, err := os.Stat(dbf.Path)
			if err != nil {
				AppLogger.Errorf("| Can`t stat file error | File [%s] | %v", dbf.Path, err)
				return

			}

			filemode := infile.Mode()

			db, err := bolt.Open(dbf.Path, filemode, &bolt.Options{Timeout: timeout})
			if err != nil {

				if !fileExists(dbf.Path) {
					AppLogger.Errorf("| Can`t open db for compaction error | DB [%s] | %v", dbf.Path, err)
					deltask := fmt.Sprintf("DELETE FROM compact WHERE path = '%s';", dbf.Path)
					_, err := cdb.Exec(deltask)
					if err != nil {
						AppLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
						continue
					}
					continue

				}

				tries := 0

				for itry := 0; itry <= opentries; itry++ {

					tries++

					db, err = bolt.Open(dbf.Path, filemode, &bolt.Options{Timeout: timeout})
					if err == nil {
						break
					}

					time.Sleep(defsleep)

				}

				if tries == opentries {
					AppLogger.Errorf("| Can`t open db for compaction error | DB [%s] | %v", dbf.Path, err)
					deltask := fmt.Sprintf("DELETE FROM compact WHERE path = '%s';", dbf.Path)
					_, err := cdb.Exec(deltask)
					if err != nil {
						AppLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
						continue
					}
					continue

				}

			}
			defer db.Close()

			err = db.CompactQuietly()
			if err != nil {
				AppLogger.Errorf("| Scheduled compaction task error | DB [%s] | %v", dbf.Path, err)
			}

			err = os.Chmod(dbf.Path, filemode)
			if err != nil {
				AppLogger.Errorf("Can`t chmod db error | DB [%s] | %v", dbf.Path, err)
				db.Close()

				deltask := fmt.Sprintf("DELETE FROM compact WHERE path = '%s';", dbf.Path)
				_, err = cdb.Exec(deltask)
				if err != nil {
					AppLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
					continue
				}

				continue

			}

			deltask := fmt.Sprintf("DELETE FROM compact WHERE path = '%s';", dbf.Path)
			_, err = cdb.Exec(deltask)
			if err != nil {
				AppLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf.Path, err)
				db.Close()
				continue
			}

			db.Close()

		}

		time.Sleep(cmpcheck)

	}

}

// Get

func wzGet() iris.Handler {
	return func(ctx iris.Context) {
		defer wg.Done()

		// Wait Group

		wg.Add(1)

		// Loggers

		GetLogger, getlogfile := getLogger()
		defer getlogfile.Close()

		// Vhost / IP Client

		ip := ctx.RemoteAddr()
		vhost := ctx.Host()

		// Shutdown

		if wshutdown {
			ctx.StatusCode(iris.StatusInternalServerError)
			//_, err := ctx.WriteString("Shutdown wZD server in progress\n")
			//if err != nil {
			//	GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
			//}
			return
		}

		uri := ctx.Path()
		method := ctx.Method()
		ifnm := ctx.GetHeader("If-None-Match")
		ifms := ctx.GetHeader("If-Modified-Since")

		badhost := true

		base := "/notfound"

		getbolt := false
		getcount := false
		getkeys := false

		readintegrity := true

		locktimeout := 60

		args := false
		cctrl := 0

		minbuffer := int64(262144)
		lowbuffer := int64(1048576)
		medbuffer := int64(67042304)
		bigbuffer := int64(536338432)

		filemode := os.FileMode(0640)

		for _, Server := range config.Server {

			if vhost == Server.HOST {

				badhost = false

				base = Server.ROOT

				getbolt = Server.GETBOLT
				getcount = Server.GETCOUNT
				getkeys = Server.GETKEYS

				readintegrity = Server.READINTEGRITY

				locktimeout = Server.LOCKTIMEOUT

				args = Server.ARGS

				cctrl = Server.CCTRL

				minbuffer = Server.MINBUFFER
				lowbuffer = Server.LOWBUFFER
				medbuffer = Server.MEDBUFFER
				bigbuffer = Server.BIGBUFFER

				cfilemode, err := strconv.ParseUint(fmt.Sprintf("%d", Server.FILEMODE), 8, 32)
				switch {
				case err != nil || cfilemode == 0:
					filemode = os.FileMode(0640)
				default:
					filemode = os.FileMode(cfilemode)
				}

				break

			}

		}

		if badhost {

			ctx.StatusCode(iris.StatusMisdirectedRequest)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Not found configured virtual host", vhost, ip)

			if debugmode {

				_, err := ctx.Writef("[ERRO] Not found configured virtual host | Virtual Host [%s]\n", vhost)
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if !args {

			params := ctx.URLParams()

			if len(params) != 0 {

				ctx.StatusCode(iris.StatusForbidden)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The query arguments is not allowed during GET request", vhost, ip)

				if debugmode {

					_, err := ctx.WriteString("[ERRO] The query arguments is not allowed during GET request\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

		}

		dir := filepath.Dir(uri)
		file := filepath.Base(uri)

		if !getbolt {

			mchregbolt := rgxbolt.MatchString(file)

			if mchregbolt {

				ctx.StatusCode(iris.StatusForbidden)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The bolt request is not allowed during GET request", vhost, ip)

				if debugmode {

					_, err := ctx.WriteString("[ERRO] The request is not allowed during GET request\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

		}

		hcount := ctx.GetHeader("KeysCount")

		if !getcount && hcount == "1" {

			ctx.StatusCode(iris.StatusForbidden)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The count request is not allowed during GET request", vhost, ip)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The request is not allowed during GET request\n")
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		hkeys := ctx.GetHeader("Keys")
		hkeysall := ctx.GetHeader("KeysAll")

		if !getkeys && (hkeys == "1" || hkeysall == "1") {

			ctx.StatusCode(iris.StatusForbidden)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The count request is not allowed during GET request", vhost, ip)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The request is not allowed during GET request\n")
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if hkeys == "1" && hkeysall == "1" {

			ctx.StatusCode(iris.StatusConflict)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t serve Keys and KeysAll header together due to conflict error", vhost, ip)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] Can`t serve Keys and KeysAll header together due to conflict error\n")
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

		}

		fromarchive := ctx.GetHeader("FromArchive")

		abs := fmt.Sprintf("%s%s/%s", base, dir, file)

		dbn := filepath.Base(dir)
		dbf := fmt.Sprintf("%s%s/%s.bolt", base, dir, dbn)
		dbk := fmt.Sprintf("%s%s/%s.bolt", base, uri, file)

		bucket := "default"
		timeout := time.Duration(locktimeout) * time.Second

		// Standart/Bolt Counter

		if dirExists(abs) && hcount == "1" {

			if !fileExists(dbk) {

				filecount, err := fileCount(abs)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t count files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count files in directory error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				_, err = ctx.Writef("%d\n", filecount)
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

				return

			}

			if fileExists(dbk) {

				db, err := bolt.Open(dbk, filemode, &bolt.Options{Timeout: timeout, ReadOnly: true})
				if err != nil {

					if !fileExists(dbk) {

						ctx.StatusCode(iris.StatusInternalServerError)
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
							if err != nil {
								GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

					tries := 0

					for itry := 0; itry <= opentries; itry++ {

						tries++

						db, err = bolt.Open(dbk, filemode, &bolt.Options{Timeout: timeout, ReadOnly: true})
						if err == nil {
							break
						}

						time.Sleep(defsleep)

					}

					if tries == opentries {

						ctx.StatusCode(iris.StatusInternalServerError)
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
							if err != nil {
								GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

				}
				defer db.Close()

				filecount, err := fileCount(abs)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t count files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count files in directory error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				keycount, err := keyCount(db, bucket)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t count keys of files in db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count keys of files in db bucket error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Writef("%d\n", (keycount + filecount - 1))
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

				db.Close()
				return

			}

			ctx.StatusCode(iris.StatusNotFound)
			return

		}

		// Standart/Bolt Keys Iterator

		if dirExists(abs) && (hkeys == "1" || hkeysall == "1") {

			var keysbuffer bytes.Buffer

			if !fileExists(dbk) {

				getkeys, err := fileKeys(abs)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t iterate files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate files in directory error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				allkeys := fmt.Sprintf("%s\n", strings.Join(getkeys, "\n"))

				err = binary.Write(&keysbuffer, Endian, []byte(allkeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Write keys names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write keys names to keysbuffer error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

				return

			}

			if fileExists(dbk) {

				uniq := true

				if hkeysall == "1" {
					uniq = false
				}

				db, err := bolt.Open(dbk, filemode, &bolt.Options{Timeout: timeout, ReadOnly: true})
				if err != nil {

					if !fileExists(dbk) {

						ctx.StatusCode(iris.StatusInternalServerError)
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
							if err != nil {
								GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

					tries := 0

					for itry := 0; itry <= opentries; itry++ {

						tries++

						db, err = bolt.Open(dbk, filemode, &bolt.Options{Timeout: timeout, ReadOnly: true})
						if err == nil {
							break
						}

						time.Sleep(defsleep)

					}

					if tries == opentries {

						ctx.StatusCode(iris.StatusInternalServerError)
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
							if err != nil {
								GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

				}
				defer db.Close()

				getkeys, err := allKeys(db, bucket, abs, uniq)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t iterate keys of files in db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate keys of files in db bucket error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				allkeys := fmt.Sprintf("%s\n", strings.Join(getkeys, "\n"))

				err = binary.Write(&keysbuffer, Endian, []byte(allkeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Write keys names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write keys names to keysbuffer error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

				db.Close()
				return

			}

			ctx.StatusCode(iris.StatusNotFound)
			return

		}

		if dirExists(abs) {

			ctx.StatusCode(iris.StatusForbidden)
			return

		}

		// Standart Reader

		if fileExists(abs) && fromarchive != "1" {

			infile, err := os.Stat(abs)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t stat file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t stat file error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

			size := infile.Size()
			hsize := strconv.FormatInt(size, 10)

			modt := infile.ModTime()
			hmodt := modt.Format(http.TimeFormat)
			tmst := modt.Unix()

			pfile, err := os.Open(abs)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t open file error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}
			defer pfile.Close()

			contbuffer := make([]byte, 512)

			csizebuffer, err := pfile.Read(contbuffer)
			if err != nil && err != io.EOF {

				ctx.StatusCode(iris.StatusInternalServerError)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | csizebuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				err = pfile.Close()
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						ctx.StatusCode(iris.StatusInternalServerError)
						_, err = ctx.WriteString("[ERRO] Close during read file error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] csizebuffer read file error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

			conttype, err := contentType(file, size, contbuffer, csizebuffer)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | contbuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				err = pfile.Close()
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during contbuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Close during contbuffer read file error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] contbuffer read file error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

			etag := fmt.Sprintf("%x-%x", tmst, size)
			scctrl := fmt.Sprintf("max-age=%d", cctrl)

			ctx.Header("Content-Type", conttype)
			ctx.Header("Content-Length", hsize)
			ctx.Header("Last-Modified", hmodt)
			//ctx.Header("Transfer-Encoding", "chunked")
			//ctx.Header("Connection", "keep-alive")
			ctx.Header("ETag", etag)
			ctx.Header("Cache-Control", scctrl)
			ctx.Header("Accept-Ranges", "bytes")

			if ifnm == etag || ifms == hmodt {

				err = pfile.Close()
				if err != nil {
					ctx.StatusCode(iris.StatusNotModified)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close after etag/modtime file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
					return
				}

				ctx.StatusCode(iris.StatusNotModified)
				return

			}

			if method == "HEAD" || method == "OPTIONS" {

				err = pfile.Close()
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close after head/options file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
					return
				}

				ctx.StatusCode(iris.StatusOK)

				return

			}

			// Accept-Ranges File Reader

			rngs := ctx.GetHeader("Range")

			if rngs != "" && method == "GET" {

				var rstart int64
				var rend int64
				var rlength int64

				reqr, err := parseByRange(rngs, size)
				if err != nil {

					ctx.StatusCode(iris.StatusRequestedRangeNotSatisfiable)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Invalid range error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				for _, hreq := range reqr {

					rstart = hreq.start
					rlength = hreq.length

				}

				rend = rstart + rlength - 1

				rsize := fmt.Sprintf("%d-%d/%s", rstart, rend, hsize)
				hrlength := strconv.FormatInt(rlength, 10)

				ctx.StatusCode(iris.StatusPartialContent)

				ctx.Header("Content-Range", rsize)
				ctx.Header("Content-Length", hrlength)

				_, err = pfile.Seek(rstart, 0)
				if err != nil {

					ctx.StatusCode(iris.StatusRequestedRangeNotSatisfiable)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t seek to position [%d] error | File [%s] | Path [%s] | %v", vhost, ip, rstart, file, abs, err)

					err = pfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during seek file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close during seek file error\n")
							if err != nil {
								GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

					if debugmode {

						_, err = ctx.Writef("[ERRO] Can`t seek to position [%d] error\n", rstart)
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				readbuffer := make([]byte, 64)

				for {

					switch {
					case rlength < minbuffer:
						readbuffer = make([]byte, rlength)
					case rlength >= minbuffer && rlength < lowbuffer:
						readbuffer = make([]byte, minbuffer)
					case rlength >= lowbuffer && rlength < bigbuffer:
						readbuffer = make([]byte, lowbuffer)
					case rlength >= bigbuffer:
						readbuffer = make([]byte, medbuffer)
					}

					sizebuffer, err := pfile.Read(readbuffer)
					if err != nil {
						if err == io.EOF {
							//GetLogger.Infof("| sizebuffer end of file | File [%s] | Path [%s] | %v", file, abs, err)
							break
						}

						ctx.StatusCode(iris.StatusInternalServerError)
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | sizebuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						err = pfile.Close()
						if err != nil {

							ctx.StatusCode(iris.StatusInternalServerError)
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

							if debugmode {

								_, err = ctx.WriteString("[ERRO] Close during read file error\n")
								if err != nil {
									GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
								}

							}

							return

						}

						if debugmode {

							_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
							if err != nil {
								GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

					_, err = ctx.Write(readbuffer[:sizebuffer])
					if err != nil {

						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)

						err = pfile.Close()
						if err != nil {

							ctx.StatusCode(iris.StatusInternalServerError)
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during readbuffer send file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

							if debugmode {

								_, err = ctx.WriteString("[ERRO] Close during readbuffer send file error\n")
								if err != nil {
									GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
								}

							}

							return

						}

						return

					}

					rlength = rlength - int64(sizebuffer)

					if rlength <= 0 {
						break
					}

				}

				err = pfile.Close()
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close after send range of file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
					return
				}

				return

			}

			// Standart File Reader

			_, err = pfile.Seek(0, 0)
			if err != nil {

				ctx.StatusCode(iris.StatusRequestedRangeNotSatisfiable)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t seek to position 0 error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				err = pfile.Close()
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during seek file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Close during seek file error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t seek to position 0 error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

			readbuffer := make([]byte, 64)

			rlength := size

			for {

				switch {
				case rlength < minbuffer:
					readbuffer = make([]byte, rlength)
				case rlength >= minbuffer && rlength < lowbuffer:
					readbuffer = make([]byte, minbuffer)
				case rlength >= lowbuffer && rlength < bigbuffer:
					readbuffer = make([]byte, lowbuffer)
				case rlength >= bigbuffer:
					readbuffer = make([]byte, medbuffer)
				}

				sizebuffer, err := pfile.Read(readbuffer)
				if err != nil {
					if err == io.EOF {
						//GetLogger.Infof("| sizebuffer end of file | File [%s] | Path [%s] | %v", file, abs, err)
						break
					}

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | sizebuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					err = pfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close during read file error\n")
							if err != nil {
								GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				_, err = ctx.Write(readbuffer[:sizebuffer])
				if err != nil {

					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)

					err = pfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during readbuffer send file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close during readbuffer send file error\n")
							if err != nil {
								GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

					return

				}

				rlength = rlength - int64(sizebuffer)

				if rlength <= 0 {
					break
				}

			}

			err = pfile.Close()
			if err != nil {
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close after send file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
				return
			}

			return

		}

		// Bolt Reader

		if dir == "/" && dbn == "/" {
			ctx.StatusCode(iris.StatusNotFound)
			return
		}

		if !fileExists(dbf) {
			ctx.StatusCode(iris.StatusNotFound)
			return
		}

		db, err := bolt.Open(dbf, filemode, &bolt.Options{Timeout: timeout, ReadOnly: true})
		if err != nil {

			if !fileExists(dbf) {

				ctx.StatusCode(iris.StatusInternalServerError)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

			tries := 0

			for itry := 0; itry <= opentries; itry++ {

				tries++

				db, err = bolt.Open(dbf, filemode, &bolt.Options{Timeout: timeout, ReadOnly: true})
				if err == nil {
					break
				}

				time.Sleep(defsleep)

			}

			if tries == opentries {

				ctx.StatusCode(iris.StatusInternalServerError)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

		}
		defer db.Close()

		keyexists, err := keyExists(db, bucket, file)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t check key of file in db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t check key of file in db bucket error\n")
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			return

		}

		if !keyexists {
			ctx.StatusCode(iris.StatusNotFound)
			db.Close()
			return
		}

		// Header Bolt Reader

		var pheader []byte

		err = db.View(func(tx *bolt.Tx) error {
			nb := tx.Bucket([]byte(bucket))
			pheader = nb.GetLimit([]byte(file), uint32(544))
			return nil
		})
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t get data header by key from db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t get data header by key from db error\n")
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			return

		}

		preadheader := bytes.NewReader(pheader)

		var readhead header

		headbuffer := make([]byte, 32)

		hsizebuffer, err := preadheader.Read(headbuffer)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Read header data from db error | File [%s] | DB [%s] | Header Buffer [%p] | %v", vhost, ip, file, dbf, headbuffer, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Read header data from db error\n")
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			return

		}

		hread := bytes.NewReader(headbuffer[:hsizebuffer])

		err = binary.Read(hread, Endian, &readhead)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Read binary header data from db error | File [%s] | DB [%s] | Header Buffer [%p] | %v", vhost, ip, file, dbf, hread, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Read binary header data from db error\n")
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			return

		}

		size := int64(readhead.Size)
		hsize := strconv.FormatUint(uint64(readhead.Size), 10)

		tmst := int64(readhead.Date)
		modt := time.Unix(tmst, 0)
		hmodt := modt.Format(http.TimeFormat)

		crc := readhead.Crcs

		contbuffer := make([]byte, 512)

		csizebuffer, err := preadheader.Read(contbuffer)
		if err != nil && err != io.EOF {

			ctx.StatusCode(iris.StatusInternalServerError)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | csizebuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] csizebuffer read file error\n")
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			return

		}

		conttype, err := contentType(file, size, contbuffer, csizebuffer)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | contbuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] contbuffer read file error\n")
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			return

		}

		etag := fmt.Sprintf("%x-%x", tmst, size)
		scctrl := fmt.Sprintf("max-age=%d", cctrl)

		ctx.Header("Content-Type", conttype)
		ctx.Header("Content-Length", hsize)
		ctx.Header("Last-Modified", hmodt)
		//ctx.Header("Transfer-Encoding", "chunked")
		//ctx.Header("Connection", "keep-alive")
		ctx.Header("ETag", etag)
		ctx.Header("Cache-Control", scctrl)
		ctx.Header("Accept-Ranges", "bytes")

		if ifnm == etag || ifms == hmodt {
			ctx.StatusCode(iris.StatusNotModified)
			db.Close()
			return
		}

		if method == "HEAD" || method == "OPTIONS" {
			ctx.StatusCode(iris.StatusOK)
			db.Close()
			return
		}

		var pdata []byte

		// Accept-Ranges Bolt Reader

		rngs := ctx.GetHeader("Range")

		if rngs != "" && method == "GET" {

			var rstart int64
			var rend int64
			var rlength int64

			reqr, err := parseByRange(rngs, size)
			if err != nil {

				ctx.StatusCode(iris.StatusRequestedRangeNotSatisfiable)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Invalid range error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				db.Close()
				return

			}

			for _, hreq := range reqr {

				rstart = hreq.start
				rlength = hreq.length

			}

			rend = rstart + rlength - 1

			rsize := fmt.Sprintf("%d-%d/%s", rstart, rend, hsize)
			hrlength := strconv.FormatInt(rlength, 10)

			err = db.View(func(tx *bolt.Tx) error {
				nb := tx.Bucket([]byte(bucket))
				pdata = nb.GetRange([]byte(file), uint32(rstart+32), uint32(rlength))
				return nil
			})
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t get data by key from db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t get data by key from db error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				db.Close()
				return

			}

			pread := bytes.NewReader(pdata)

			ctx.StatusCode(iris.StatusPartialContent)

			ctx.Header("Content-Range", rsize)
			ctx.Header("Content-Length", hrlength)

			readbuffer := make([]byte, 64)

			for {

				switch {
				case rlength < minbuffer:
					readbuffer = make([]byte, rlength)
				case rlength >= minbuffer && rlength < lowbuffer:
					readbuffer = make([]byte, minbuffer)
				case rlength >= lowbuffer && rlength < bigbuffer:
					readbuffer = make([]byte, lowbuffer)
				case rlength >= bigbuffer:
					readbuffer = make([]byte, medbuffer)
				}

				sizebuffer, err := pread.Read(readbuffer)
				if err != nil {
					if err == io.EOF {
						//GetLogger.Infof("| sizebuffer end of file | File [%s] | DB [%s] | %v", file, dbf, err)
						break
					}

					ctx.StatusCode(iris.StatusInternalServerError)
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | sizebuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
						if err != nil {
							GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Write(readbuffer[:sizebuffer])
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					db.Close()
					return

				}

				rlength = rlength - int64(sizebuffer)

				if rlength <= 0 {
					break
				}

			}

			db.Close()
			return

		}

		// Standart Bolt Reader

		err = db.View(func(tx *bolt.Tx) error {
			nb := tx.Bucket([]byte(bucket))
			pdata = nb.GetOffset([]byte(file), uint32(32))
			return nil
		})
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t get data by key from db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t get data by key from db error\n")
				if err != nil {
					GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			return

		}

		pread := bytes.NewReader(pdata)

		if readintegrity && crc != 0 {

			fullbuffer := new(bytes.Buffer)

			_, err = fullbuffer.ReadFrom(pread)
			if err != nil && err != io.EOF {

				ctx.StatusCode(iris.StatusInternalServerError)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t read data to fullbuffer error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t read data to fullbuffer error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				db.Close()
				return

			}

			tbl := crc32.MakeTable(0xEDB88320)
			rcrc := crc32.Checksum(fullbuffer.Bytes(), tbl)

			if rcrc != crc {

				ctx.StatusCode(iris.StatusInternalServerError)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | CRC read file error | File [%s] | DB [%s] | Have CRC [%v] | Awaiting CRC [%v]", vhost, ip, file, dbf, rcrc, crc)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] CRC read file error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				db.Close()
				return

			}

			_, err = ctx.Write(fullbuffer.Bytes())
			if err != nil {
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				db.Close()
				return
			}

			db.Close()
			return

		}

		readbuffer := make([]byte, 64)

		rlength := size

		for {

			switch {
			case rlength < minbuffer:
				readbuffer = make([]byte, rlength)
			case rlength >= minbuffer && rlength < lowbuffer:
				readbuffer = make([]byte, minbuffer)
			case rlength >= lowbuffer && rlength < bigbuffer:
				readbuffer = make([]byte, lowbuffer)
			case rlength >= bigbuffer:
				readbuffer = make([]byte, medbuffer)
			}

			sizebuffer, err := pread.Read(readbuffer)
			if err != nil {
				if err == io.EOF {
					//GetLogger.Infof("| sizebuffer end of file | File [%s] | DB [%s] | %v", file, dbf, err)
					break
				}

				ctx.StatusCode(iris.StatusInternalServerError)
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | sizebuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
					if err != nil {
						GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				db.Close()
				return

			}

			_, err = ctx.Write(readbuffer[:sizebuffer])
			if err != nil {
				GetLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				db.Close()
				return
			}

			rlength = rlength - int64(sizebuffer)

			if rlength <= 0 {
				break
			}

		}

		db.Close()

	}

}

// Put

func wzPut(keymutex *mmutex.Mutex, cdb *sql.DB) iris.Handler {
	return func(ctx iris.Context) {
		defer wg.Done()

		// Wait Group

		wg.Add(1)

		// Loggers

		PutLogger, putlogfile := putLogger()
		defer putlogfile.Close()

		// Vhost / IP Client

		ip := ctx.RemoteAddr()
		vhost := ctx.Host()

		// Shutdown

		if wshutdown {
			ctx.StatusCode(iris.StatusInternalServerError)
			//_, err := ctx.WriteString("Shutdown wZD server in progress\n")
			//if err != nil {
			//	PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
			//}
			return
		}

		uri := ctx.Path()
		params := ctx.URLParams()
		archive := ctx.GetHeader("Archive")
		length := ctx.GetHeader("Content-Length")
		ctype := ctx.GetHeader("Content-Type")

		badhost := true

		base := "/notfound"

		upload := false

		compaction := true

		nonunique := false

		writeintegrity := true

		trytimes := 60
		locktimeout := 60

		fmaxsize := int64(1048576)

		minbuffer := int64(262144)
		lowbuffer := int64(1048576)
		medbuffer := int64(67042304)
		bigbuffer := int64(536338432)

		filemode := os.FileMode(0640)
		dirmode := os.FileMode(0750)

		deldir := false

		var vfilemode int64 = 640

		for _, Server := range config.Server {

			if vhost == Server.HOST {

				badhost = false

				base = Server.ROOT

				upload = Server.UPLOAD

				compaction = Server.COMPACTION

				nonunique = Server.NONUNIQUE

				writeintegrity = Server.WRITEINTEGRITY

				trytimes = Server.TRYTIMES
				locktimeout = Server.LOCKTIMEOUT

				fmaxsize = Server.FMAXSIZE

				minbuffer = Server.MINBUFFER
				lowbuffer = Server.LOWBUFFER
				medbuffer = Server.MEDBUFFER
				bigbuffer = Server.BIGBUFFER

				cfilemode, err := strconv.ParseUint(fmt.Sprintf("%d", Server.FILEMODE), 8, 32)
				switch {
				case err != nil || cfilemode == 0:
					filemode = os.FileMode(0640)
					vfilemode, _ = strconv.ParseInt(strconv.FormatInt(int64(filemode), 8), 8, 32)
				default:
					filemode = os.FileMode(cfilemode)
					vfilemode, _ = strconv.ParseInt(strconv.FormatInt(int64(filemode), 8), 8, 32)
				}

				cdirmode, err := strconv.ParseUint(fmt.Sprintf("%d", Server.DIRMODE), 8, 32)
				switch {
				case err != nil || cdirmode == 0:
					dirmode = os.FileMode(0750)
				default:
					dirmode = os.FileMode(cdirmode)
				}

				deldir = Server.DELDIR

				break

			}

		}

		if badhost {

			ctx.StatusCode(iris.StatusMisdirectedRequest)
			PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Not found configured virtual host", vhost, ip)

			if debugmode {

				_, err := ctx.Writef("[ERRO] Not found configured virtual host | Virtual Host [%s]\n", vhost)
				if err != nil {
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if !upload {

			ctx.StatusCode(iris.StatusForbidden)
			PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Upload disabled", vhost, ip)

			if debugmode {

				_, err := ctx.Writef("[ERRO] Upload disabled | Virtual Host [%s]\n", vhost)
				if err != nil {
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if len(params) != 0 {

			ctx.StatusCode(iris.StatusBadRequest)
			PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The query arguments is not allowed during PUT request", vhost, ip)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The query arguments is not allowed during PUT request\n")
				if err != nil {
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		mchctype := rgxctype.MatchString(ctype)

		if mchctype {

			ctx.StatusCode(iris.StatusBadRequest)
			PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The multipart query is not allowed during PUT request", vhost, ip)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The multipart query is not allowed during PUT request\n")
				if err != nil {
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		clength, err := strconv.ParseInt(length, 10, 64)
		if err != nil {

			ctx.StatusCode(iris.StatusBadRequest)
			PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Content length error during PUT request | Content-Length [%s] | %v", vhost, ip, length, err)

			if debugmode {

				_, err = ctx.WriteString("Content length error during PUT request\n")
				if err != nil {
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if clength == 0 {

			ctx.StatusCode(iris.StatusBadRequest)
			PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The body was empty during PUT request | Content-Length [%s] | %v", vhost, ip, length, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] The body was empty during PUT request\n")
				if err != nil {
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		now := time.Now()
		sec := now.Unix()

		dir := filepath.Dir(uri)
		file := filepath.Base(uri)

		abs := fmt.Sprintf("%s%s/%s", base, dir, file)
		ddir := fmt.Sprintf("%s%s", base, dir)

		dbn := filepath.Base(dir)
		dbf := fmt.Sprintf("%s%s/%s.bolt", base, dir, dbn)

		bucket := "default"
		timeout := time.Duration(locktimeout) * time.Second

		if file == "/" {

			ctx.StatusCode(iris.StatusBadRequest)
			PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | No given file name error | File [%s]", vhost, ip, file)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] No given file name error\n")
				if err != nil {
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if !dirExists(ddir) {
			err := os.MkdirAll(ddir, dirmode)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t create directory error | Directory [%s] | %v", vhost, ip, ddir, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t create directory error\n")
					if err != nil {
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

			err = os.Chmod(ddir, dirmode)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t chmod directory error | Directory [%s] | %v", vhost, ip, ddir, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t chmod directory error\n")
					if err != nil {
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

		}

		// Standart Writer

		if archive != "1" || clength > fmaxsize {

			if fileExists(dbf) && nonunique {

				db, err := bolt.Open(dbf, filemode, &bolt.Options{Timeout: timeout, ReadOnly: true})
				if err != nil {

					if !fileExists(dbf) {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

					tries := 0

					for itry := 0; itry <= opentries; itry++ {

						tries++

						db, err = bolt.Open(dbf, filemode, &bolt.Options{Timeout: timeout, ReadOnly: true})
						if err == nil {
							break
						}

						time.Sleep(defsleep)

					}

					if tries == opentries {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

				}
				defer db.Close()

				keyexists, err := keyExists(db, bucket, file)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t check key of file in db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t check key of file in db bucket error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				if keyexists {

					ctx.StatusCode(iris.StatusConflict)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t upload standart file due to conflict with duplicate key/file name in db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t upload standart file due to conflict with duplicate key/file name in db error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				db.Close()

			}

			key := false

			for i := 0; i < trytimes; i++ {

				if key = keymutex.TryLock(abs); key {
					break
				}

				time.Sleep(defsleep)

			}

			if key {

				wfile, err := os.OpenFile(abs, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, filemode)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open/create file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open/create file error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					keymutex.Unlock(abs)
					return

				}
				defer wfile.Close()

				err = os.Chmod(abs, filemode)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t chmod file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t chmod file error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				endbuffer := make([]byte, 64)

				rlength := clength

				if clength > minbuffer {

					for {

						switch {
						case rlength >= minbuffer && rlength < lowbuffer:
							endbuffer = make([]byte, minbuffer)
						case rlength >= lowbuffer && rlength < medbuffer:
							endbuffer = make([]byte, lowbuffer)
						case rlength >= bigbuffer:
							endbuffer = make([]byte, medbuffer)
						}

						sizebuffer, err := ctx.Request().Body.Read(endbuffer)
						if err != nil {
							if err == io.EOF {

								if sizebuffer == 0 {
									//PutLogger.Infof("| sizebuffer end of file | File [%s] | Path [%s] | %v", file, abs, err)
									break
								}

								_, err = wfile.Write(endbuffer[:sizebuffer])
								if err != nil {

									ctx.StatusCode(iris.StatusInternalServerError)
									PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Write sizebuffer during write to file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

									err = wfile.Close()
									if err != nil {

										ctx.StatusCode(iris.StatusInternalServerError)
										PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during write file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

										if debugmode {

											_, err = ctx.WriteString("[ERRO] Close during write file error\n")
											if err != nil {
												PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
											}

										}

										keymutex.Unlock(abs)
										return

									}

									if debugmode {

										_, err = ctx.WriteString("[ERRO] Write sizebuffer during write to file error\n")
										if err != nil {
											PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
										}

									}

									keymutex.Unlock(abs)
									return

								}

								break

							}

							ctx.StatusCode(iris.StatusInternalServerError)
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | sizebuffer write file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

							if debugmode {

								_, err = ctx.WriteString("[ERRO] sizebuffer write file error\n")
								if err != nil {
									PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
								}

							}

							break

						}

						_, err = wfile.Write(endbuffer[:sizebuffer])
						if err != nil {

							ctx.StatusCode(iris.StatusInternalServerError)
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Write sizebuffer last write to file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

							err = wfile.Close()
							if err != nil {

								ctx.StatusCode(iris.StatusInternalServerError)
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close last write file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

								if debugmode {

									_, err = ctx.WriteString("[ERRO] Close last write file error\n")
									if err != nil {
										PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
									}

								}

								keymutex.Unlock(abs)
								return

							}

							if debugmode {

								_, err = ctx.WriteString("[ERRO] Write sizebuffer last write to file error\n")
								if err != nil {
									PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
								}

							}

							keymutex.Unlock(abs)
							return

						}

						rlength = rlength - int64(sizebuffer)

						if rlength <= 0 {
							break
						}

					}

					upfile, err := os.Stat(abs)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t stat uploaded file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t stat uploaded file error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						keymutex.Unlock(abs)
						return

					}

					realsize := upfile.Size()

					if realsize != clength {

						ctx.StatusCode(iris.StatusBadRequest)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The body length != real length during PUT request | Content-Length [%s] | Real Size [%d]", vhost, ip, length, realsize)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] The body length != real length during PUT request\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						if fileExists(abs) {
							err = removeFile(abs, ddir, deldir)
							if err != nil {

								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t remove bad uploaded file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

								if debugmode {

									_, err = ctx.WriteString("[ERRO] Can`t remove bad uploaded file error\n")
									if err != nil {
										PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
									}

								}

								keymutex.Unlock(abs)
								return

							}

						}

						keymutex.Unlock(abs)
						return

					}

					keymutex.Unlock(abs)
					return

				}

				uendbuffer := new(bytes.Buffer)

				_, err = uendbuffer.ReadFrom(ctx.Request().Body)
				if err != nil && err != io.EOF {

					ctx.StatusCode(iris.StatusInternalServerError)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t read request body data error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t read request body data error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				realsize := int64(len(uendbuffer.Bytes()))

				if realsize == 0 {

					ctx.StatusCode(iris.StatusBadRequest)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The body was empty during PUT request | Content-Length [%s] | %v", vhost, ip, length, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] The body was empty during PUT request\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				if realsize != clength {

					ctx.StatusCode(iris.StatusBadRequest)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The body length != real length during PUT request | Content-Length [%s] | Real Size [%d]", vhost, ip, length, realsize)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] The body length != real length during PUT request\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				_, err = wfile.Write(uendbuffer.Bytes())
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Write full buffer write to file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					err = wfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close full write file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close full write file error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						keymutex.Unlock(abs)
						return

					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write full buffer to file error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				keymutex.Unlock(abs)
				return

			} else {

				ctx.StatusCode(iris.StatusInternalServerError)
				PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Timeout mmutex lock error | File [%s] | Path [%s]", vhost, ip, file, abs)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Timeout mmutex lock error\n")
					if err != nil {
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

		}

		// Bolt Writer

		if archive == "1" {

			if dbn == "/" {
				ctx.StatusCode(iris.StatusForbidden)
				PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t upload file to virtual host root error | File [%s]", vhost, ip, file)

				if debugmode {

					_, err := ctx.WriteString("[ERRO] Can`t upload file to virtual host root error\n")
					if err != nil {
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t upload file to virtual host root error", vhost, ip)
					}

				}

				return

			}

			key := false

			for i := 0; i < trytimes; i++ {

				if key = keymutex.TryLock(dbf); key {
					break
				}

				time.Sleep(defsleep)

			}

			if key {

				wcrc := uint32(0)

				db, err := bolt.Open(dbf, filemode, &bolt.Options{Timeout: timeout})
				if err != nil {

					if !fileExists(dbf) {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open/create db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t open/create db file error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						keymutex.Unlock(dbf)
						return

					}

					tries := 0

					for itry := 0; itry <= opentries; itry++ {

						tries++

						db, err = bolt.Open(dbf, filemode, &bolt.Options{Timeout: timeout})
						if err == nil {
							break
						}

						time.Sleep(defsleep)

					}

					if tries == opentries {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open/create db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t open/create db file error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						keymutex.Unlock(dbf)
						return

					}

				}
				defer db.Close()

				err = os.Chmod(dbf, filemode)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t chmod db error | DB [%s] | %v", vhost, ip, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t chmod db error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				err = db.Update(func(tx *bolt.Tx) error {
					_, err := tx.CreateBucketIfNotExists([]byte(bucket))
					if err != nil {
						return err
					}
					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t write file to db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t write file to db bucket error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				keyexists, err := keyExists(db, bucket, file)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t check key of file in db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t check key of file in db bucket error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				rawbuffer := new(bytes.Buffer)
				_, err = rawbuffer.ReadFrom(ctx.Request().Body)
				if err != nil && err != io.EOF {

					ctx.StatusCode(iris.StatusInternalServerError)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t read request body data error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t read request body data error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				realsize := int64(len(rawbuffer.Bytes()))

				if realsize == 0 {

					ctx.StatusCode(iris.StatusBadRequest)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The body was empty during PUT request | Content-Length [%s] | %v", vhost, ip, length, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] The body was empty during PUT request\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if realsize != clength {

					ctx.StatusCode(iris.StatusBadRequest)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The body length != real length during PUT request | Content-Length [%s] | Real Size [%d]", vhost, ip, length, realsize)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] The body length != real length during PUT request\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				endbuffer := new(bytes.Buffer)

				if writeintegrity {

					var readbuffer bytes.Buffer
					tee := io.TeeReader(rawbuffer, &readbuffer)

					tbl := crc32.MakeTable(0xEDB88320)

					crcdata := new(bytes.Buffer)

					_, err = crcdata.ReadFrom(tee)
					if err != nil && err != io.EOF {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t read tee crc data error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t read tee crc data error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					wcrc = crc32.Checksum(crcdata.Bytes(), tbl)

					head := header{
						Size: uint64(realsize), Date: uint32(sec), Mode: uint16(vfilemode), Uuid: uint16(Uid), Guid: uint16(Gid), Comp: uint8(0), Encr: uint8(0), Crcs: wcrc, Rsvr: uint64(0),
					}

					err = binary.Write(endbuffer, Endian, head)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Write header data to db error | File [%s] | DB [%s] | Header [%v] | %v", vhost, ip, file, dbf, head, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Write header data to db error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					_, err = endbuffer.ReadFrom(&readbuffer)
					if err != nil && err != io.EOF {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t read readbuffer data error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t read readbuffer data error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				} else {

					head := header{
						Size: uint64(realsize), Date: uint32(sec), Mode: uint16(vfilemode), Uuid: uint16(Uid), Guid: uint16(Gid), Comp: uint8(0), Encr: uint8(0), Crcs: wcrc, Rsvr: uint64(0),
					}

					err = binary.Write(endbuffer, Endian, head)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Write binary header data to db error | File [%s] | DB [%s] | Header [%v] | %v", vhost, ip, file, dbf, head, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Write binary header data to db error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					_, err = endbuffer.ReadFrom(rawbuffer)
					if err != nil && err != io.EOF {

						ctx.StatusCode(iris.StatusInternalServerError)
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t read rawbuffer data error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t read rawbuffer data error\n")
							if err != nil {
								PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				}

				err = db.Update(func(tx *bolt.Tx) error {
					nb := tx.Bucket([]byte(bucket))
					err = nb.Put([]byte(file), []byte(endbuffer.Bytes()))
					if err != nil {
						return err
					}

					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t write file to db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t write file to db bucket error\n")
						if err != nil {
							PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if keyexists && compaction && cmpsched {

					mdbf := fmt.Sprintf("%x", md5.Sum([]byte(dbf)))
					upsert := fmt.Sprintf("INSERT INTO compact(id,path,machid,count) VALUES ('%s', '%s', '%s', '1') ON CONFLICT (id) DO UPDATE SET count = compact.count + 1;", mdbf, dbf, machid)

					switch dbdriver {
					case "sqlite":
						upsert = fmt.Sprintf("INSERT INTO compact(id,path,machid,count) VALUES ('%s', '%s', '%s', '1') ON CONFLICT (id) DO UPDATE SET count = compact.count + 1;", mdbf, dbf, machid)
					case "pgsql":
						upsert = fmt.Sprintf("INSERT INTO compact(id,path,machid,count) VALUES ('%s', '%s', '%s', '1') ON CONFLICT (id) DO UPDATE SET count = compact.count + 1;", mdbf, dbf, machid)
					case "mysql":
						upsert = fmt.Sprintf("INSERT INTO compact(id,path,machid,count) VALUES ('%s', '%s', '%s', '1') ON DUPLICATE KEY UPDATE count = compact.count + 1;", mdbf, dbf, machid)
					}

					_, err := cdb.Exec(upsert)
					if err != nil {

						PutLogger.Errorf("| Insert/Update data error | ID [%s] | PATH [%s] | %v", mdbf, dbf, err)
						PutLogger.Errorf("| Compaction will be started on the fly | DB [%s]", dbf)

						err = db.CompactQuietly()
						if err != nil {
							PutLogger.Errorf("| On the fly compaction error | DB [%s] | %v", dbf, err)
						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				}

				db.Close()
				keymutex.Unlock(dbf)
				return

			} else {

				ctx.StatusCode(iris.StatusInternalServerError)
				PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Timeout mmutex lock error | File [%s] | DB [%s]", vhost, ip, file, dbf)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Timeout mmutex lock error\n")
					if err != nil {
						PutLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

		}

	}

}

// Delete

func wzDel(keymutex *mmutex.Mutex, cdb *sql.DB) iris.Handler {
	return func(ctx iris.Context) {
		defer wg.Done()

		// Wait Group

		wg.Add(1)

		// Loggers

		DelLogger, dellogfile := delLogger()
		defer dellogfile.Close()

		// Vhost / IP Client

		ip := ctx.RemoteAddr()
		vhost := ctx.Host()

		// Shutdown

		if wshutdown {
			ctx.StatusCode(iris.StatusInternalServerError)
			//_, err := ctx.WriteString("Shutdown wZD server in progress\n")
			//if err != nil {
			//	DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
			//}
			return
		}

		uri := ctx.Path()
		params := ctx.URLParams()

		badhost := true

		delete := false

		base := "/notfound"

		compaction := true

		trytimes := 60
		locktimeout := 60

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
			DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Not found configured virtual host", vhost, ip)

			if debugmode {

				_, err := ctx.Writef("[ERRO] Not found configured virtual host | Virtual Host [%s]\n", vhost)
				if err != nil {
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if !delete {

			ctx.StatusCode(iris.StatusForbidden)
			DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Delete disabled", vhost, ip)

			if debugmode {

				_, err := ctx.Writef("[ERRO] Delete disabled | Virtual Host [%s]\n", vhost)
				if err != nil {
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if len(params) != 0 {

			ctx.StatusCode(iris.StatusBadRequest)
			DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The query arguments is not allowed during DELETE request", vhost, ip)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The query arguments is not allowed during DELETE request\n")
				if err != nil {
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
				DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The delete bolt request is not allowed during DELETE request", vhost, ip)

				if debugmode {

					_, err := ctx.WriteString("[ERRO] The delete bolt request is not allowed during DELETE request\n")
					if err != nil {
						DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

		}

		abs := fmt.Sprintf("%s%s/%s", base, dir, file)
		ddir := fmt.Sprintf("%s%s", base, dir)

		dbn := filepath.Base(dir)
		dbf := fmt.Sprintf("%s%s/%s.bolt", base, dir, dbn)

		bucket := "default"
		timeout := time.Duration(locktimeout) * time.Second

		if file == "/" {

			ctx.StatusCode(iris.StatusBadRequest)
			DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | No given file name error | File [%s]", vhost, ip, file)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] No given file name error\n")
				if err != nil {
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if !dirExists(ddir) {

			ctx.StatusCode(iris.StatusNotFound)
			DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t find directory error | Directory [%s]", vhost, ip, ddir)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] Can`t find directory error\n")
				if err != nil {
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if !fileExists(abs) && !fileExists(dbf) {
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

			if fileExists(abs) && fromarchive != "1" {
				err := removeFile(abs, ddir, deldir)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t remove file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t remove file error\n")
						if err != nil {
							DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
			DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Timeout mmutex lock error | File [%s] | DB [%s]", vhost, ip, file, dbf)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] Timeout mmutex lock error\n")
				if err != nil {
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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

			db, err := bolt.Open(dbf, filemode, &bolt.Options{Timeout: timeout})
			if err != nil {

				if !fileExists(dbf) {

					ctx.StatusCode(iris.StatusInternalServerError)
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
						if err != nil {
							DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					keymutex.Unlock(dbf)
					return

				}

				tries := 0

				for itry := 0; itry <= opentries; itry++ {

					tries++

					db, err = bolt.Open(dbf, filemode, &bolt.Options{Timeout: timeout})
					if err == nil {
						break
					}

					time.Sleep(defsleep)

				}

				if tries == opentries {

					ctx.StatusCode(iris.StatusInternalServerError)
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
						if err != nil {
							DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					keymutex.Unlock(dbf)
					return

				}

			}
			defer db.Close()

			keyexists, err := keyExists(db, bucket, file)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t check key of file in db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t check key of file in db bucket error\n")
					if err != nil {
						DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				db.Close()
				keymutex.Unlock(dbf)
				return

			}

			if keyexists {

				err = db.Update(func(tx *bolt.Tx) error {
					nb := tx.Bucket([]byte(bucket))
					err = nb.Delete([]byte(file))
					if err != nil {
						return err
					}

					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t remove file from db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t remove file from db bucket error\n")
						if err != nil {
							DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				keycount, err := keyCount(db, bucket)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t count keys of files in db bucket error | DB [%s] | %v", vhost, ip, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count keys of files in db bucket error\n")
						if err != nil {
							DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if keycount == 0 {

					err := removeFileDB(dbf, ddir, deldir)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t remove db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t remove db file error\n")
							if err != nil {
								DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					if compaction && cmpsched {

						deltask := fmt.Sprintf("DELETE FROM compact WHERE path = '%s';", dbf)
						_, err = cdb.Exec(deltask)
						if err != nil {
							DelLogger.Errorf("| Delete compaction task error | DB [%s] | %v", dbf, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if compaction && cmpsched {

					mdbf := fmt.Sprintf("%x", md5.Sum([]byte(dbf)))
					upsert := fmt.Sprintf("INSERT INTO compact(id,path,machid,count) VALUES ('%s', '%s', '%s', '1') ON CONFLICT (id) DO UPDATE SET count = compact.count + 1;", mdbf, dbf, machid)

					switch dbdriver {
					case "sqlite":
						upsert = fmt.Sprintf("INSERT INTO compact(id,path,machid,count) VALUES ('%s', '%s', '%s', '1') ON CONFLICT (id) DO UPDATE SET count = compact.count + 1;", mdbf, dbf, machid)
					case "pgsql":
						upsert = fmt.Sprintf("INSERT INTO compact(id,path,machid,count) VALUES ('%s', '%s', '%s', '1') ON CONFLICT (id) DO UPDATE SET count = compact.count + 1;", mdbf, dbf, machid)
					case "mysql":
						upsert = fmt.Sprintf("INSERT INTO compact(id,path,machid,count) VALUES ('%s', '%s', '%s', '1') ON DUPLICATE KEY UPDATE count = compact.count + 1;", mdbf, dbf, machid)
					}

					_, err = cdb.Exec(upsert)
					if err != nil {

						DelLogger.Errorf("| Insert/Update data error | ID [%s] | PATH [%s] | %v", mdbf, dbf, err)
						DelLogger.Errorf("| Compaction will be started on the fly | DB [%s]", dbf)

						err = db.CompactQuietly()
						if err != nil {
							DelLogger.Errorf("| On the fly compaction error | DB [%s] | %v", dbf, err)
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
			DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t find file in db error | File [%s] | DB [%s]", vhost, ip, file, dbf)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t find file in db error\n")
				if err != nil {
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			keymutex.Unlock(dbf)
			return

		} else {

			ctx.StatusCode(iris.StatusInternalServerError)
			DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Timeout mmutex lock error | File [%s] | DB [%s]", vhost, ip, file, dbf)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] Timeout mmutex lock error\n")
				if err != nil {
					DelLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

	}

}

// SQL Database Connections

func GetSql() (*sql.DB, error) {

	AppLogger, applogfile := appLogger()
	defer applogfile.Close()

	i := 0

	var dbtype string
	var sqlinfo string
	var logname string

	switch dbdriver {
	case "sqlite":
		dbtype = "sqlite3"
		logname = "Sqlite"
		sqlinfo = dbfile
	case "pgsql":
		dbtype = "postgres"
		logname = "PostgreSQL"
		sqlinfo = fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable", dbhost, dbport, dbname, dbuser, dbpass)
	case "mysql":
		dbtype = "mysql"
		logname = "MySQL"
		sqlinfo = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", dbuser, dbpass, dbhost, dbport, dbname)
	default:
		dbtype = "sqlite3"
		logname = "Sqlite"
		sqlinfo = dbfile
	}

	for {

		i++

		cdb, err := sql.Open(dbtype, sqlinfo)
		if err != nil {
			AppLogger.Errorf("Try open connection to [%s] (Instance Main) [%s] | %v", logname, sqlinfo, err)
		}

		err = cdb.Ping()
		if err == nil {
			AppLogger.Infof("Successfully connected to [%s] (Instance Main) [%s]", logname, sqlinfo)
			switch {
			case dbdriver == "pgsql" || dbdriver == "mysql":
				cdb.SetMaxOpenConns(dbconn)
				cdb.SetMaxIdleConns(dbconn)
			}
			return cdb, err
		}

		AppLogger.Errorf("| Try connect to [%s] (Instance Main) [%s] | %v", logname, sqlinfo, err)

		if i >= 30 {
			AppLogger.Errorf("| Connect to [%s] (Instance Main) [%s] | %v", logname, sqlinfo, err)
			return cdb, err
		}

		time.Sleep(defsleep)

	}

}

// Determine Endianess Handler

func DetectEndian() {

	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		Endian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		Endian = binary.BigEndian
	default:
		fmt.Printf("Can`t determine native endianness error\n")
		os.Exit(1)
	}

}

// Detect Daemon User/Group Handler

func DetectUser() {

	user, err := user.Current()
	if err != nil {
		fmt.Printf("Can`t determine current user error | %v\n", err)
		os.Exit(1)
	}

	Uid, err = strconv.ParseInt(user.Uid, 10, 16)
	if err != nil {
		fmt.Printf("Can`t int convert current user uid error | %v\n", err)
		os.Exit(1)
	}

	Gid, err = strconv.ParseInt(user.Gid, 10, 16)
	if err != nil {
		fmt.Printf("Can`t int convert current user gid error | %v\n", err)
		os.Exit(1)
	}

}

// Get PID

func GetPID() (gpid string, fpid string) {

	gpid = fmt.Sprintf("%d", os.Getpid())
	fpid = fmt.Sprintf("%s\n", gpid)

	return gpid, fpid

}

// Get Machine ID Helper

func MachineID() {

	var err error

	machid, err = machineid.ID()
	if err != nil {
		machid = "nomachineid"
	}

}

// Files Count Handler

func fileCount(dirpath string) (cnt int, err error) {

	cnt = 0

	allfiles, err := ioutil.ReadDir(dirpath)
	if err != nil {
		return 0, err
	}

	for _, file := range allfiles {
		if !file.IsDir() {
			cnt++
		}
	}

	return cnt, nil

}

// File Exists Handler

func fileExists(filename string) bool {

	if fi, err := os.Stat(filename); err == nil {

		if fi.Mode().IsRegular() {
			return true
		}

	}

	return false

}

// Dir Exists Handler

func dirExists(filename string) bool {

	if fi, err := os.Stat(filename); err == nil {

		if fi.Mode().IsDir() {
			return true
		}

	}

	return false

}

// Files Keys Iterator Handler

func fileKeys(dirpath string) (keys []string, err error) {

	keys = []string{}
	var k string

	last := filepath.Base(dirpath)
	bname := fmt.Sprintf("%s.bolt", last)

	allfiles, err := ioutil.ReadDir(dirpath)
	if err != nil {
		return keys, err
	}

	for _, file := range allfiles {

		if bname != file.Name() {
			k = file.Name()
			keys = append(keys, k)
		}

	}

	return keys, nil

}

// Remove File Handler

func removeFile(file string, directory string, deldir bool) error {

	err := os.Remove(file)
	if err != nil {
		return err
	}

	if deldir {

		dir, err := os.Open(directory)
		if err != nil {
			return err
		}
		defer dir.Close()

		_, err = dir.Readdir(1)
		if err != nil {
			if err == io.EOF {
				err = os.Remove(directory)
				if err != nil {
					return err
				}

				return err

			}

			return err

		}

	}

	return err

}

// DB Key Exists Handler

func keyExists(db *bolt.DB, bucket string, file string) (exkey bool, err error) {

	exkey = false

	err = db.View(func(tx *bolt.Tx) error {

		nb := tx.Bucket([]byte(bucket))
		pos := nb.Cursor()

		skey := ""

		for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

			skey = fmt.Sprintf("%s", inkey)

			if skey == file {
				exkey = true
				break
			}

		}

		return nil

	})

	return exkey, err

}

// DB Keys Count Handler

func keyCount(db *bolt.DB, bucket string) (cnt int, err error) {

	cnt = 0

	var sts bolt.BucketStats

	err = db.View(func(tx *bolt.Tx) error {

		nb := tx.Bucket([]byte(bucket))
		sts = nb.Stats()
		cnt = sts.KeyN
		return nil

	})

	return cnt, err

}

// DB/File Unique Keys Iterator Helper

func allKeys(db *bolt.DB, bucket string, dirpath string, uniq bool) (keys []string, err error) {

	allkeys := []string{}
	compare := map[string]bool{}
	keys = []string{}
	var k string

	last := filepath.Base(dirpath)
	bname := fmt.Sprintf("%s.bolt", last)

	err = db.View(func(tx *bolt.Tx) error {

		nb := tx.Bucket([]byte(bucket))
		pos := nb.Cursor()

		for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {
			k = fmt.Sprintf("%s", inkey)
			allkeys = append(allkeys, k)
		}

		return nil

	})

	if err != nil {
		return keys, err
	}

	allfiles, err := ioutil.ReadDir(dirpath)
	if err != nil {
		return keys, err
	}

	for _, file := range allfiles {

		if bname != file.Name() {
			k = file.Name()
			allkeys = append(allkeys, k)
		}

	}

	if uniq {

		for v := range allkeys {

			if !compare[allkeys[v]] {
				compare[allkeys[v]] = true
				keys = append(keys, allkeys[v])
			}

		}

	} else {

		keys = allkeys

	}

	sort.Strings(keys)

	return keys, err

}

// DB Remove File Handler

func removeFileDB(file string, directory string, deldir bool) error {

	err := os.Remove(file)
	if err != nil {
		return err
	}

	if deldir {

		dir, err := os.Open(directory)
		if err != nil {
			return err
		}
		defer dir.Close()

		_, err = dir.Readdir(2)
		if err != nil {
			if err == io.EOF {
				err = os.Remove(directory)
				if err != nil {
					return err
				}

				return err

			}

			return err

		}

	}

	return err

}

// Content Type Helper

func contentType(filename string, filesize int64, contbuffer []byte, csizebuffer int) (conttype string, err error) {

	conttype = mime.TypeByExtension(filepath.Ext(filename))

	if conttype == "" && filesize >= 512 {

		conttype = http.DetectContentType(contbuffer[:csizebuffer])
		return conttype, err

	}

	return conttype, err

}

// Accept Ranges Helper

func parseByRange(rngs string, size int64) ([]reqRange, error) {

	rngerr := errors.New("bad range")

	var ranges []reqRange

	const headb = "bytes="
	if !strings.HasPrefix(rngs, headb) {
		return nil, rngerr
	}

	for _, rngobj := range strings.Split(rngs[len(headb):], ",") {

		rngobj = strings.TrimSpace(rngobj)
		if rngobj == "" {
			continue
		}

		i := strings.Index(rngobj, "-")
		if i < 0 {
			return nil, rngerr
		}

		start, end := strings.TrimSpace(rngobj[:i]), strings.TrimSpace(rngobj[i+1:])

		var r reqRange

		if start == "" {

			i, err := strconv.ParseInt(end, 10, 64)
			if err != nil {
				return nil, rngerr
			}

			if i > size {
				i = size
			}

			r.start = size - i
			r.length = size - r.start

		} else {

			i, err := strconv.ParseInt(start, 10, 64)
			if err != nil || i >= size || i < 0 {
				return nil, rngerr
			}

			r.start = i

			if end == "" {

				r.length = size - r.start

			} else {

				i, err := strconv.ParseInt(end, 10, 64)
				if err != nil || r.start > i {
					return nil, rngerr
				}

				if i >= size {
					i = size - 1
				}

				r.length = i - r.start + 1

			}

		}

		ranges = append(ranges, r)

	}

	return ranges, nil

}

// Loggers

func appLogger() (*golog.Logger, *os.File) {

	AppLogger := golog.New()

	applogfile := AppLogFile()

	if debugmode {
		AppLogger.SetLevel("debug")
		AppLogger.AddOutput(applogfile)
	} else {
		AppLogger.SetLevel("warn")
		AppLogger.SetOutput(applogfile)
	}

	return AppLogger, applogfile

}

func getLogger() (*golog.Logger, *os.File) {

	GetLogger := golog.New()

	getlogfile := GetLogFile()

	if debugmode {
		GetLogger.SetLevel("debug")
		GetLogger.AddOutput(getlogfile)
	} else {
		GetLogger.SetLevel("warn")
		GetLogger.SetOutput(getlogfile)
	}

	return GetLogger, getlogfile

}

func putLogger() (*golog.Logger, *os.File) {

	PutLogger := golog.New()

	putlogfile := PutLogFile()

	if debugmode {
		PutLogger.SetLevel("debug")
		PutLogger.AddOutput(putlogfile)
	} else {
		PutLogger.SetLevel("warn")
		PutLogger.SetOutput(putlogfile)
	}

	return PutLogger, putlogfile

}

func delLogger() (*golog.Logger, *os.File) {

	DelLogger := golog.New()

	dellogfile := DelLogFile()

	if debugmode {
		DelLogger.SetLevel("debug")
		DelLogger.AddOutput(dellogfile)
	} else {
		DelLogger.SetLevel("warn")
		DelLogger.SetOutput(dellogfile)
	}

	return DelLogger, dellogfile

}

// Log Paths

func todayAppFilename() string {
	logfile := fmt.Sprintf("%s/app.log", logdir)
	return logfile
}

func todayGetFilename() string {
	logfile := fmt.Sprintf("%s/get.log", logdir)
	return logfile
}

func todayPutFilename() string {
	logfile := fmt.Sprintf("%s/put.log", logdir)
	return logfile
}

func todayDelFilename() string {
	logfile := fmt.Sprintf("%s/del.log", logdir)
	return logfile
}

// Log Files

func AppLogFile() *os.File {

	filename := todayAppFilename()
	applogfile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logmode)
	if err != nil {
		fmt.Printf("Can`t open/create 'app' log file error | File [%s] | %v", filename, err)
		os.Exit(1)
	}

	err = os.Chmod(filename, logmode)
	if err != nil {
		fmt.Printf("Can`t chmod log file error | File [%s] | %v", filename, err)
		os.Exit(1)
	}

	return applogfile
}

func GetLogFile() *os.File {
	filename := todayGetFilename()
	getlogfile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logmode)
	if err != nil {
		fmt.Printf("Can`t open/create 'get' log file error | File [%s] | %v", filename, err)
		os.Exit(1)
	}

	err = os.Chmod(filename, logmode)
	if err != nil {
		fmt.Printf("Can`t chmod log file error | File [%s] | %v", filename, err)
		os.Exit(1)
	}

	return getlogfile
}

func PutLogFile() *os.File {
	filename := todayPutFilename()
	putlogfile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logmode)
	if err != nil {
		fmt.Printf("Can`t open/create 'put' log file error | File [%s] | %v", filename, err)
		os.Exit(1)
	}

	err = os.Chmod(filename, logmode)
	if err != nil {
		fmt.Printf("Can`t chmod log file error | File [%s] | %v", filename, err)
		os.Exit(1)
	}

	return putlogfile
}

func DelLogFile() *os.File {
	filename := todayDelFilename()
	dellogfile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logmode)
	if err != nil {
		fmt.Printf("Can`t open/create 'del' log file error | File [%s] | %v", filename, err)
		os.Exit(1)
	}

	err = os.Chmod(filename, logmode)
	if err != nil {
		fmt.Printf("Can`t chmod log file error | File [%s] | %v", filename, err)
		os.Exit(1)
	}

	return dellogfile
}

// Check Options With Boolean Functions

func check(bvar bool, sec string, name string, val string, perm string, ferr func(string, string, string, string)) {

	if !bvar {
		ferr(sec, name, val, perm)
	}

}

func doexit(sec string, name string, val string, perm string) {
	fmt.Printf("Bad option value error | Section [%s] | Name [%s] | Value [%v] | Permissible Value [%s]\n", sec, name, val, perm)
	os.Exit(1)
}

func RBInt(i int, min int, max int) bool {

	switch {
	case i >= min && i <= max:
		return true
	default:
		return false
	}

}

func RBInt64(i int64, min int64, max int64) bool {

	switch {
	case i >= min && i <= max:
		return true
	default:
		return false
	}

}

// Init Function

func init() {

	var version string = "1.0.0"
	var vprint bool = false
	var help bool = false

	// Command Line Options

	flag.StringVar(&configfile, "config", configfile, "--config=/etc/wzd/wzd.conf")
	flag.BoolVar(&debugmode, "debug", debugmode, "--debug enable debug mode")
	flag.BoolVar(&vprint, "version", vprint, "--version prints version")
	flag.BoolVar(&help, "help", help, "--help prints help")

	flag.Parse()

	switch {
	case vprint:
		fmt.Printf("wZD Version: %s\n", version)
		os.Exit(0)
	case help:
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Load Configuration

	if _, err := toml.DecodeFile(configfile, &config); err != nil {
		fmt.Printf("Can`t decode config file error | File [%s] | %v\n", configfile, err)
		os.Exit(1)
	}

	// Check Global Options

	mchreadtimeout := RBInt(config.Global.READTIMEOUT, 0, 86400)
	check(mchreadtimeout, "[global]", "readtimeout", fmt.Sprintf("%d", config.Global.READTIMEOUT), "from 0 to 86400", doexit)

	mchreadheadertimeout := RBInt(config.Global.READHEADERTIMEOUT, 0, 86400)
	check(mchreadheadertimeout, "[global]", "readheadertimeout", fmt.Sprintf("%d", config.Global.READHEADERTIMEOUT), "from 0 to 86400", doexit)

	mchidletimeout := RBInt(config.Global.IDLETIMEOUT, 0, 86400)
	check(mchidletimeout, "[global]", "idletimeout", fmt.Sprintf("%d", config.Global.IDLETIMEOUT), "from 0 to 86400", doexit)

	mchwritetimeout := RBInt(config.Global.WRITETIMEOUT, 0, 86400)
	check(mchwritetimeout, "[global]", "writetimeout", fmt.Sprintf("%d", config.Global.WRITETIMEOUT), "from 0 to 86400", doexit)

	if config.Global.REALHEADER != "" {
		rgxrealheader := regexp.MustCompile("^([a-zA-Z0-9-_]+)")
		mchrealheader := rgxrealheader.MatchString(config.Global.REALHEADER)
		check(mchrealheader, "[global]", "realheader", config.Global.REALHEADER, "ex. X-Real-IP", doexit)
	} else {
		config.Global.REALHEADER = "X-Real-IP"
	}

	if config.Global.CHARSET != "" {
		rgxcharset := regexp.MustCompile("^([a-zA-Z0-9-])+")
		mchcharset := rgxcharset.MatchString(config.Global.CHARSET)
		check(mchcharset, "[global]", "charset", config.Global.CHARSET, "ex. UTF-8", doexit)
	} else {
		config.Global.CHARSET = "UTF-8"
	}

	rgxdebugmode := regexp.MustCompile("^(?i)(true|false)$")
	mchdebugmode := rgxdebugmode.MatchString(fmt.Sprintf("%t", config.Global.DEBUGMODE))
	check(mchdebugmode, "[global]", "debugmode", (fmt.Sprintf("%t", config.Global.DEBUGMODE)), "true or false", doexit)

	if config.Global.PIDFILE != "" {
		rgxpidfile := regexp.MustCompile("^(/[^/\x00]*)+/?$")
		mchpidfile := rgxpidfile.MatchString(config.Global.PIDFILE)
		check(mchpidfile, "[global]", "pidfile", config.Global.PIDFILE, "ex. /run/wzd/wzd.pid", doexit)
	} else {
		config.Global.PIDFILE = "/run/wzd/wzd.pid"
	}

	if config.Global.LOGDIR != "" {
		rgxlogdir := regexp.MustCompile("^(/[^/\x00]*)+/?$")
		mchlogdir := rgxlogdir.MatchString(config.Global.LOGDIR)
		check(mchlogdir, "[global]", "logdir", config.Global.LOGDIR, "ex. /var/log/wzd", doexit)
	} else {
		config.Global.LOGDIR = "/var/log/wzd"
	}

	rgxlogmode := regexp.MustCompile("^([0-7]{3})")
	mchlogmode := rgxlogmode.MatchString(fmt.Sprintf("%d", config.Global.LOGMODE))
	check(mchlogmode, "[global]", "logmode", fmt.Sprintf("%d", config.Global.LOGMODE), "from 0600 to 0666", doexit)

	mchdefsleep := RBInt(config.Global.DEFSLEEP, 1, 5)
	check(mchdefsleep, "[global]", "defsleep", fmt.Sprintf("%d", config.Global.DEFSLEEP), "from 1 to 5", doexit)

	mchopentries := RBInt(config.Global.OPENTRIES, 1, 1000)
	check(mchopentries, "[global]", "opentries", fmt.Sprintf("%d", config.Global.OPENTRIES), "from 1 to 1000", doexit)

	if config.Global.DBDRIVER != "" {
		rgxdbdriver := regexp.MustCompile("^(?i)(sqlite|pgsql|mysql)$")
		mchdbdriver := rgxdbdriver.MatchString(config.Global.DBDRIVER)
		check(mchdbdriver, "[global]", "dbdriver", config.Global.DBDRIVER, "sqlite or pgsql or mysql", doexit)
	} else {
		config.Global.DBDRIVER = "sqlite"
	}

	if config.Global.DBFILE != "" {
		rgxdbfile := regexp.MustCompile("^(/[^/\x00]*)+/?$")
		mchdbfile := rgxdbfile.MatchString(config.Global.DBFILE)
		check(mchdbfile, "[global]", "dbfile", config.Global.DBFILE, "ex. /var/lib/wzd/wzd.sqlite3", doexit)
	} else {
		config.Global.DBFILE = "/var/lib/wzd/wzd.sqlite3"
	}

	if config.Global.DBHOST != "" || config.Global.DBPORT != 0 || config.Global.DBNAME != "" || config.Global.DBDRIVER == "pgsql" || config.Global.DBDRIVER == "mysql" {

		rgxdbhost := regexp.MustCompile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
		rgxdbname := regexp.MustCompile("^([a-zA-Z0-9-_]+)")
		mchdbhost := rgxdbhost.MatchString(config.Global.DBHOST)
		mchdbport := RBInt(config.Global.OPENTRIES, 1, 65535)
		mchdbname := rgxdbname.MatchString(config.Global.DBNAME)
		mchdbconn := RBInt(config.Global.DBCONN, 1, 1024)
		check(mchdbhost, "[global]", "dbhost", config.Global.DBHOST, "ex. 127.0.0.1", doexit)
		check(mchdbport, "[global]", "dbport", fmt.Sprintf("%d", config.Global.DBPORT), "from 1 to 65535", doexit)
		check(mchdbname, "[global]", "dbname", config.Global.DBNAME, "ex. wzd", doexit)
		check(mchdbconn, "[global]", "dbconn", fmt.Sprintf("%d", config.Global.DBCONN), "from 1 to 1024", doexit)

	}

	rgxcmpsched := regexp.MustCompile("^(?i)(true|false)$")
	mchcmpsched := rgxcmpsched.MatchString(fmt.Sprintf("%t", config.Global.CMPSCHED))
	check(mchcmpsched, "[global]", "cmpsched", (fmt.Sprintf("%t", config.Global.CMPSCHED)), "true or false", doexit)

	if config.Global.CMPSCHED {

		mchcmptime := RBInt(config.Global.CMPTIME, 1, 365)
		check(mchcmptime, "[global]", "cmptime", fmt.Sprintf("%d", config.Global.CMPTIME), "from 1 to 365", doexit)

		mchcmpcount := RBInt(config.Global.CMPCOUNT, 10, 10000)
		check(mchcmpcount, "[global]", "cmpcount", fmt.Sprintf("%d", config.Global.CMPCOUNT), "from 10 to 10000", doexit)

		mchcmpcheck := RBInt(config.Global.CMPCHECK, 1, 5)
		check(mchcmpcheck, "[global]", "cmpcheck", fmt.Sprintf("%d", config.Global.CMPCHECK), "from 1 to 5", doexit)

	}

	// Log Mode

	clogmode, err := strconv.ParseUint(fmt.Sprintf("%d", config.Global.LOGMODE), 8, 32)
	switch {
	case err != nil || clogmode == 0:
		logmode = os.FileMode(0640)
	default:
		logmode = os.FileMode(clogmode)
	}

	// Output Important Global Configuration Options

	AppLogger, applogfile := appLogger()
	defer applogfile.Close()

	AppLogger.Warnf("| Starting wZD Server [%s]", version)

	switch {
	case config.Global.CMPSCHED:
		AppLogger.Warnf("| Compaction Scheduler [ENABLED]")
		AppLogger.Warnf("| Compaction Database Driver [%s]", config.Global.DBDRIVER)
		AppLogger.Warnf("| Compaction Time > [%d] days", config.Global.CMPTIME)
		AppLogger.Warnf("| Compaction Count > [%d] keys", config.Global.CMPCOUNT)
		AppLogger.Warnf("| Compaction Scheduler Check Every [%d] seconds", config.Global.CMPCHECK)
	default:
		AppLogger.Warnf("| Compaction Scheduler [DISABLED]")
	}

	// Check Server Options

	var section string

	rgxroot := regexp.MustCompile("^(/[^/\x00]*)+/?$")
	rgxupload := regexp.MustCompile("^(?i)(true|false)$")
	rgxdelete := regexp.MustCompile("^(?i)(true|false)$")
	rgxcompaction := regexp.MustCompile("^(?i)(true|false)$")
	rgxgetbolt := regexp.MustCompile("^(?i)(true|false)$")
	rgxgetcount := regexp.MustCompile("^(?i)(true|false)$")
	rgxgetkeys := regexp.MustCompile("^(?i)(true|false)$")
	rgxnonunique := regexp.MustCompile("^(?i)(true|false)$")
	rgxwriteintegrity := regexp.MustCompile("^(?i)(true|false)$")
	rgxreadintegrity := regexp.MustCompile("^(?i)(true|false)$")
	rgxargs := regexp.MustCompile("^(?i)(true|false)$")
	rgxfilemode := regexp.MustCompile("^([0-7]{3})")
	rgxdirmode := regexp.MustCompile("^([0-7]{3})")
	rgxdelbolt := regexp.MustCompile("^(?i)(true|false)$")
	rgxdeldir := regexp.MustCompile("^(?i)(true|false)$")

	for _, Server := range config.Server {

		section = "[server] | Host ["
		section = fmt.Sprintf("%s%s%s", section, Server.HOST, "]")

		if Server.HOST == "" {
			fmt.Printf("Empty server host error | %s%s%s\n", section, "]", " | ex. host=\"localhost\"")
			os.Exit(1)
		}

		mchroot := rgxroot.MatchString(Server.ROOT)
		check(mchroot, section, "root", Server.ROOT, "ex. /var/storage/localhost", doexit)

		mchupload := rgxupload.MatchString(fmt.Sprintf("%t", Server.UPLOAD))
		check(mchupload, section, "upload", (fmt.Sprintf("%t", Server.UPLOAD)), "true or false", doexit)

		mchdelete := rgxdelete.MatchString(fmt.Sprintf("%t", Server.DELETE))
		check(mchdelete, section, "delete", (fmt.Sprintf("%t", Server.DELETE)), "true or false", doexit)

		mchcompaction := rgxcompaction.MatchString(fmt.Sprintf("%t", Server.COMPACTION))
		check(mchcompaction, section, "compaction", (fmt.Sprintf("%t", Server.COMPACTION)), "true or false", doexit)

		mchgetbolt := rgxgetbolt.MatchString(fmt.Sprintf("%t", Server.GETBOLT))
		check(mchgetbolt, section, "getbolt", (fmt.Sprintf("%t", Server.GETBOLT)), "true or false", doexit)

		mchgetcount := rgxgetcount.MatchString(fmt.Sprintf("%t", Server.GETCOUNT))
		check(mchgetcount, section, "getcount", (fmt.Sprintf("%t", Server.GETCOUNT)), "true or false", doexit)

		mchgetkeys := rgxgetkeys.MatchString(fmt.Sprintf("%t", Server.GETKEYS))
		check(mchgetkeys, section, "getkeys", (fmt.Sprintf("%t", Server.GETKEYS)), "true or false", doexit)

		mchnonunique := rgxnonunique.MatchString(fmt.Sprintf("%t", Server.NONUNIQUE))
		check(mchnonunique, section, "nonunique", (fmt.Sprintf("%t", Server.NONUNIQUE)), "true or false", doexit)

		mchwriteintegrity := rgxwriteintegrity.MatchString(fmt.Sprintf("%t", Server.WRITEINTEGRITY))
		check(mchwriteintegrity, section, "writeintegrity", (fmt.Sprintf("%t", Server.WRITEINTEGRITY)), "true or false", doexit)

		mchreadintegrity := rgxreadintegrity.MatchString(fmt.Sprintf("%t", Server.READINTEGRITY))
		check(mchreadintegrity, section, "readintegrity", (fmt.Sprintf("%t", Server.READINTEGRITY)), "true or false", doexit)

		mchtrytimes := RBInt(Server.TRYTIMES, 1, 1000)
		check(mchtrytimes, section, "trytimes", (fmt.Sprintf("%d", Server.TRYTIMES)), "from 1 to 1000", doexit)

		mchlocktimeout := RBInt(Server.LOCKTIMEOUT, 1, 3600)
		check(mchlocktimeout, section, "locktimeout", (fmt.Sprintf("%d", Server.LOCKTIMEOUT)), "from 1 to 3600", doexit)

		mchfmaxsize := RBInt64(Server.FMAXSIZE, 1, 536338432)
		check(mchfmaxsize, section, "fmaxsize", (fmt.Sprintf("%d", Server.FMAXSIZE)), "from 1 to 536338432", doexit)

		mchargs := rgxargs.MatchString(fmt.Sprintf("%t", Server.ARGS))
		check(mchargs, section, "args", (fmt.Sprintf("%t", Server.ARGS)), "true or false", doexit)

		mchcctrl := RBInt(Server.CCTRL, 0, 2147483647)
		check(mchcctrl, section, "cctrl", (fmt.Sprintf("%d", Server.CCTRL)), "from 0 to 2147483647", doexit)

		mchminbuffer := RBInt64(Server.MINBUFFER, 4096, 524288)
		check(mchminbuffer, section, "minbuffer", (fmt.Sprintf("%d", Server.MINBUFFER)), "from 4096 to 524288", doexit)

		mchlowbuffer := RBInt64(Server.LOWBUFFER, 1048576, 33521152)
		check(mchlowbuffer, section, "lowbuffer", (fmt.Sprintf("%d", Server.LOWBUFFER)), "from 1048576 to 33521152", doexit)

		mchmedbuffer := RBInt64(Server.MEDBUFFER, 67042304, 268169216)
		check(mchmedbuffer, section, "medbuffer", (fmt.Sprintf("%d", Server.MEDBUFFER)), "from 67042304 to 268169216", doexit)

		mchbigbuffer := RBInt64(Server.BIGBUFFER, 536338432, 2147483647)
		check(mchbigbuffer, section, "bigbuffer", (fmt.Sprintf("%d", Server.BIGBUFFER)), "from 536338432 to 2147483647", doexit)

		mchfilemode := rgxfilemode.MatchString(fmt.Sprintf("%d", Server.FILEMODE))
		check(mchfilemode, section, "filemode", (fmt.Sprintf("%d", Server.FILEMODE)), "from 0600 to 0666", doexit)

		mchdirmode := rgxdirmode.MatchString(fmt.Sprintf("%d", Server.DIRMODE))
		check(mchdirmode, section, "dirmode", (fmt.Sprintf("%d", Server.DIRMODE)), "from 0700 to 0777", doexit)

		mchdelbolt := rgxdelbolt.MatchString(fmt.Sprintf("%t", Server.DELBOLT))
		check(mchdelbolt, section, "delbolt", (fmt.Sprintf("%t", Server.DELBOLT)), "true or false", doexit)

		mchdeldir := rgxdeldir.MatchString(fmt.Sprintf("%t", Server.DELDIR))
		check(mchdeldir, section, "deldir", (fmt.Sprintf("%t", Server.DELDIR)), "true or false", doexit)

		// Output Important Server Configuration Options

		AppLogger.Warnf("| Host [%s] | Max File Size [%d]", Server.HOST, Server.FMAXSIZE)

		switch {
		case Server.COMPACTION && config.Global.CMPSCHED:
			AppLogger.Warnf("| Host [%s] | Compaction [ENABLED]", Server.HOST)
		default:
			AppLogger.Warnf("| Host [%s] | Compaction [DISABLED]", Server.HOST)
		}

		switch {
		case Server.WRITEINTEGRITY:
			AppLogger.Warnf("| Host [%s] | Write Integrity [ENABLED]", Server.HOST)
		default:
			AppLogger.Warnf("| Host [%s] | Write Integrity [DISABLED]", Server.HOST)
		}

		switch {
		case Server.READINTEGRITY:
			AppLogger.Warnf("| Host [%s] | Read Integrity [ENABLED]", Server.HOST)
		default:
			AppLogger.Warnf("| Host [%s] | Read Integrity [DISABLED]", Server.HOST)
		}

		switch {
		case Server.ARGS:
			AppLogger.Warnf("| Host [%s] | Query Arguments [ENABLED]", Server.HOST)
		default:
			AppLogger.Warnf("| Host [%s] | Query Arguments [DISABLED]", Server.HOST)
		}

		switch {
		case Server.GETBOLT:
			AppLogger.Warnf("| Host [%s] | Get Bolt Files [ENABLED]", Server.HOST)
		default:
			AppLogger.Warnf("| Host [%s] | Get Bolt Files [DISABLED]", Server.HOST)
		}

		switch {
		case Server.GETCOUNT:
			AppLogger.Warnf("| Host [%s] | Get Count Keys/Files [ENABLED]", Server.HOST)
		default:
			AppLogger.Warnf("| Host [%s] | Get Count Keys/Files [DISABLED]", Server.HOST)
		}

		switch {
		case Server.GETKEYS:
			AppLogger.Warnf("| Host [%s] | Get Names Keys/Files [ENABLED]", Server.HOST)
		default:
			AppLogger.Warnf("| Host [%s] | Get Names Keys/Files [DISABLED]", Server.HOST)
		}

		switch {
		case Server.NONUNIQUE:
			AppLogger.Warnf("| Host [%s] | Non-Unique Keys/Files [ENABLED]", Server.HOST)
		default:
			AppLogger.Warnf("| Host [%s] | Non-Unique Keys/Files [DISABLED]", Server.HOST)
		}

		AppLogger.Warnf("| Host [%s] | Cache-Control Time [%d]", Server.HOST, Server.CCTRL)

		switch {
		case Server.DELBOLT:
			AppLogger.Warnf("| Host [%s] | Delete Bolt Files [ENABLED]", Server.HOST)
		default:
			AppLogger.Warnf("| Host [%s] | Delete Bolt Files [DISABLED]", Server.HOST)
		}

		switch {
		case Server.DELDIR:
			AppLogger.Warnf("| Host [%s] | Delete Directory [ENABLED]", Server.HOST)
		default:
			AppLogger.Warnf("| Host [%s] | Delete Directory [DISABLED]", Server.HOST)
		}

	}

	// Debug Option

	if !debugmode {
		debugmode = config.Global.DEBUGMODE
	}

}

// Main Function

func main() {

	// System Handling

	DetectEndian()
	DetectUser()

	// Get Machine ID

	MachineID()

	// Get Pid

	gpid, fpid := GetPID()

	// Log Directory

	logdir = config.Global.LOGDIR

	if !dirExists(logdir) {
		fmt.Printf("Log directory not exists error | Path: [%s]\n", logdir)
		os.Exit(1)
	}

	AppLogger, applogfile := appLogger()
	defer applogfile.Close()

	// PID File

	pidfile = config.Global.PIDFILE

	switch {
	case fileExists(pidfile):
		err := os.Remove(pidfile)
		if err != nil {
			AppLogger.Errorf("| Can`t remove pid file error | File [%s] | %v", pidfile, err)
			fmt.Printf("Can`t remove pid file error | File [%s] | %v\n", pidfile, err)
			os.Exit(1)
		}
		fallthrough
	default:
		err := ioutil.WriteFile(pidfile, []byte(fpid), 0644)
		if err != nil {
			AppLogger.Errorf("| Can`t create pid file error | File [%s] | %v", pidfile, err)
			fmt.Printf("Can`t create pid file error | File [%s] | %v\n", pidfile, err)
			os.Exit(1)
		}

	}

	// Default Timers / Tries

	defsleep = time.Duration(config.Global.DEFSLEEP) * time.Second
	opentries = config.Global.OPENTRIES

	// SQL Database Configuration

	dbdriver = config.Global.DBDRIVER
	dbfile = config.Global.DBFILE
	dbhost = config.Global.DBHOST
	dbport = config.Global.DBPORT
	dbname = config.Global.DBNAME
	dbuser = config.Global.DBUSER
	dbpass = config.Global.DBPASS
	dbconn = config.Global.DBCONN

	cmptime = config.Global.CMPTIME
	cmpcount = config.Global.CMPCOUNT
	cmpcheck = time.Duration(config.Global.CMPCHECK) * time.Second

	// Pid Handling

	AppLogger.Warnf("wZD server running with pid: %s", gpid)

	// Map Mutex

	keymutex := mmutex.NewMMutex()

	// SQL Database Connection

	cdb, err := GetSql()
	if err != nil {
		AppLogger.Errorf("| Connect to database failed error (Instance Main) | %v", err)
		fmt.Printf("Connect to database failed error (Instance Main) | %v\n", err)
		os.Exit(1)
	}
	defer cdb.Close()

	ctable := fmt.Sprintf("CREATE TABLE IF NOT EXISTS compact (id varchar(32) NOT NULL, path text NOT NULL, machid varchar(32) NOT NULL DEFAULT 0, time timestamp NOT NULL DEFAULT current_timestamp, count bigint NOT NULL DEFAULT 0, PRIMARY KEY(id));")
	_, err = cdb.Exec(ctable)
	if err != nil {
		AppLogger.Errorf("| Can`t create compact table in database [%s] error (Instance Main) error | %v", ctable, err)
		fmt.Printf("Can`t create compact table in database [%s] error (Instance Main) | %v\n", ctable, err)
		os.Exit(1)
	}

	// Go Compaction Scheduler

	cmpsched = config.Global.CMPSCHED

	if cmpsched {
		go compactScheduler(cdb)
	}

	// Web Server

	app := iris.New()

	// Iris Satrtup Log Debug Options

	switch debugmode {
	case true:
		app.Logger().SetLevel("debug")
		app.Logger().AddOutput(applogfile)
	case false:
		app.Logger().SetLevel("warn")
		app.Logger().SetOutput(applogfile)
	}

	app.Use(logger.New())
	app.Use(recover.New())

	// Web Routing

	app.Get("/{directory:path}", wzGet())
	app.Head("/{directory:path}", wzGet())
	app.Options("/{directory:path}", wzGet())
	app.Put("/{directory:path}", wzPut(keymutex, cdb))
	app.Delete("/{directory:path}", wzDel(keymutex, cdb))

	// Interrupt Handler

	iris.RegisterOnInterrupt(func() {

		// Shutdown Server

		AppLogger.Warnf("Stop receive new requests")
		AppLogger.Warnf("Capture interrupt")
		AppLogger.Warnf("Notify go routines about interrupt")

		shutdown = true

		// Wait Go Routines

		AppLogger.Warnf("Awaiting all go routines")

		wg.Wait()

		AppLogger.Warnf("Finished all go routines")

		timeout := 5 * time.Second

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		AppLogger.Warnf("Shutdown wZD server completed")

		err := app.Shutdown(ctx)
		if err != nil {
			fmt.Printf("Something wrong when shutdown wZD Server | %v\n", err)
			os.Exit(1)
		}

		// Remove PID File

		if fileExists(pidfile) {
			err := os.Remove(pidfile)
			if err != nil {
				AppLogger.Errorf("| Can`t remove pid file error | File [%s] | %v", pidfile, err)
				fmt.Printf("Can`t remove pid file error | File [%s] | %v\n", pidfile, err)
				os.Exit(1)
			}
		}

	})

	// Web Listen Settings

	bindaddr := config.Global.BINDADDR
	switch {
	case bindaddr == "":
		bindaddr = "127.0.0.1:9699"
	}

	charset := config.Global.CHARSET
	realheader := config.Global.REALHEADER

	// Start WebServer

	srv := &http.Server{
		Addr:              bindaddr,
		ReadTimeout:       readtimeout,
		ReadHeaderTimeout: readheadertimeout,
		IdleTimeout:       idletimeout,
		WriteTimeout:      writetimeout,
		MaxHeaderBytes:    1 << 20,
	}

	err = app.Run(iris.Server(srv), iris.WithoutInterruptHandler, iris.WithoutBodyConsumptionOnUnmarshal, iris.WithCharset(charset), iris.WithRemoteAddrHeader(realheader), iris.WithOptimizations, iris.WithConfiguration(iris.Configuration{
		DisablePathCorrection: false,
		EnablePathEscape:      true,
		TimeFormat:            "Mon, 02 Jan 2006 15:04:05 GMT",
		Charset:               charset,
	}))
	if err != nil && !shutdown {
		fmt.Printf("Something wrong when starting wZD Server | %v\n", err)
		os.Exit(1)
	}

}
