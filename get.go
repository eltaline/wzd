package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/eltaline/bolt"
	"github.com/kataras/iris"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Get

// ZDGet : GET/HEAD/OPTIONS methods
func ZDGet() iris.Handler {
	return func(ctx iris.Context) {
		defer wg.Done()

		// Wait Group

		wg.Add(1)

		// Loggers

		getLogger, getlogfile := GetLogger()
		defer getlogfile.Close()

		// Shutdown

		if wshutdown {
			ctx.StatusCode(iris.StatusInternalServerError)
			// _, err := ctx.WriteString("Shutdown wZD server in progress\n")
			// if err != nil {
			//	getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip , err)
			// }
			return
		}

		// Headers

		ip := ctx.RemoteAddr()
		cip := net.ParseIP(ip)
		vhost := strings.Split(ctx.Host(), ":")[0]

		uri := ctx.Path()
		method := ctx.Method()
		ifnm := ctx.GetHeader("If-None-Match")
		ifms := ctx.GetHeader("If-Modified-Since")

		hkeys := ctx.GetHeader("Keys")
		hkeysall := ctx.GetHeader("KeysAll")
		hkeysfiles := ctx.GetHeader("KeysFiles")
		hkeysarchive := ctx.GetHeader("KeysArchive")

		hinfo := ctx.GetHeader("KeysInfo")
		hinfoall := ctx.GetHeader("KeysInfoAll")
		hinfofiles := ctx.GetHeader("KeysInfoFiles")
		hinfoarchive := ctx.GetHeader("KeysInfoArchive")

		hcount := ctx.GetHeader("KeysCount")
		hcountall := ctx.GetHeader("KeysCountAll")
		hcountfiles := ctx.GetHeader("KeysCountFiles")
		hcountarchive := ctx.GetHeader("KeysCountArchive")

		hlimit := ctx.GetHeader("Limit")
		hoffset := ctx.GetHeader("Offset")

		hjson := ctx.GetHeader("JSON")

		//		hconfig := ctx.GetHeader("Config")

		fromarchive := ctx.GetHeader("FromArchive")

		badhost := true
		badip := true

		base := "/notfound"

		options := ""
		headorigin := ""
		xframe := ""

		getbolt := false
		getkeys := false
		getinfo := false
		getcount := false

		limit := int64(-1)
		offset := int64(-1)

		readintegrity := true

		opentries := 5
		locktimeout := 5

		args := false
		cctrl := 0

		minbuffer := int64(262144)
		lowbuffer := int64(1048576)
		medbuffer := int64(67108864)
		bigbuffer := int64(536870912)

		filemode := os.FileMode(0640)

		gzstatic := false

		log4xx := true

		dir := filepath.Dir(uri)
		file := filepath.Base(uri)

		mchregcrcbolt := rgxcrcbolt.MatchString(file)

		for _, Server := range config.Server {

			if vhost == Server.HOST {

				badhost = false

				base = Server.ROOT

				for _, Vhost := range getallow {

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

				options = Server.OPTIONS
				headorigin = Server.HEADORIGIN
				xframe = Server.XFRAME

				getbolt = Server.GETBOLT
				getkeys = Server.GETKEYS
				getinfo = Server.GETINFO
				getcount = Server.GETCOUNT

				readintegrity = Server.READINTEGRITY

				opentries = Server.OPENTRIES
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

				gzstatic = Server.GZSTATIC

				log4xx = Server.LOG4XX

				break

			}

		}

		if badhost {

			ctx.StatusCode(iris.StatusMisdirectedRequest)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 421 | Not found configured virtual host", vhost, ip)
			}

			if debugmode {

				_, err := ctx.Writef("[ERRO] Not found configured virtual host | Virtual Host [%s]\n", vhost)
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if badip {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Forbidden", vhost, ip)
			}

			if debugmode {

				_, err := ctx.Writef("[ERRO] Not found allowed ip | Virtual Host [%s]\n", vhost)
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if !args {

			params := ctx.URLParams()

			if len(params) != 0 {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The query arguments is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err := ctx.WriteString("[ERRO] The query arguments is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

		}

		if mchregcrcbolt {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Restricted to download .crcbolt file error | File [%s]", vhost, ip, file)
			}

			if debugmode {

				_, err := ctx.WriteString("[ERRO] Restricted to download .crcbolt file error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

		}

		if !getbolt {

			mchregbolt := rgxbolt.MatchString(file)

			if mchregbolt {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The direct bolt request is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err := ctx.WriteString("[ERRO] The direct bolt request is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

		}

		if !getkeys && (hkeys == "1" || hkeysall == "1" || hkeysfiles == "1" || hkeysarchive == "1") {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The keys request is not allowed during GET request", vhost, ip)
			}

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The keys request is not allowed during GET request\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if !getinfo && (hinfo == "1" || hinfoall == "1" || hinfofiles == "1" || hinfoarchive == "1") {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The keys info request is not allowed during GET request", vhost, ip)
			}

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The keys info request is not allowed during GET request\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if !getcount && (hcount == "1" || hcountall == "1" || hcountfiles == "1" || hcountarchive == "1") {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The count request is not allowed during GET request", vhost, ip)
			}

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The count request is not allowed during GET request\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		abs := fmt.Sprintf("%s%s/%s", base, dir, file)
		gzabs := fmt.Sprintf("%s%s/%s.gz", base, dir, file)
		gzfile := fmt.Sprintf("%s.gz", file)

		dbn := filepath.Base(dir)
		dbf := fmt.Sprintf("%s%s/%s.bolt", base, dir, dbn)
		dbk := fmt.Sprintf("%s%s/%s.bolt", base, uri, file)

		if gzstatic && FileExists(gzabs) {
			abs = gzabs
			file = gzfile
		}

		bucket := ""
		ibucket := "index"
		//		sbucket := "size"
		//		tbucket := "time"

		timeout := time.Duration(locktimeout) * time.Second

		var err error

		// Check Limit/Offset Headers for GET keys/keys with info requests

		if hlimit != "" {

			limit, err = strconv.ParseInt(hlimit, 10, 64)
			if err != nil {

				ctx.StatusCode(iris.StatusBadRequest)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Limit uint error during GET keys/keys with info request | Limit [%s] | %v", vhost, ip, hlimit, err)
				}

				if debugmode {

					_, err = ctx.WriteString("Limit uint error during GET keys/keys with info request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

		}

		if hoffset != "" {

			offset, err = strconv.ParseInt(hoffset, 10, 64)
			if err != nil {

				ctx.StatusCode(iris.StatusBadRequest)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Offset uint error during GET keys/keys with info request | Offset [%s] | %v", vhost, ip, hoffset, err)
				}

				if debugmode {

					_, err = ctx.WriteString("Offset uint error during GET keys/keys with info request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

		}

		// Standart/Bolt Keys Iterator

		istrue, ccnm := StringOne(hkeys, hkeysall, hkeysfiles, hkeysarchive)

		switch {

		case istrue && (ccnm == 1 || ccnm == 2):

			var keysbuffer bytes.Buffer

			uniq := true

			if ccnm == 2 {
				uniq = false
			}

			if DirExists(abs) && !FileExists(dbk) {

				getkeys, err := FileKeys(abs, limit, offset)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate files in directory error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				filekeys := ""

				if hjson == "1" {
					jkeys, _ := json.Marshal(getkeys)
					filekeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
				} else {
					filekeys = fmt.Sprintf("%s\n", strings.Join(getkeys, "\n"))
				}

				err = binary.Write(&keysbuffer, Endian, []byte(filekeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write key names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write key names to keysbuffer error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if FileExists(dbk) {

				db, err := BoltOpenRead(dbk, filemode, timeout, opentries, freelist)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}
				defer db.Close()

				getkeys, err := AllKeys(db, ibucket, abs, uniq, limit, offset)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate keys of files in index db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate keys of files in index db bucket error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				allkeys := ""

				if hjson == "1" {
					jkeys, _ := json.Marshal(getkeys)
					allkeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
				} else {
					allkeys = fmt.Sprintf("%s\n", strings.Join(getkeys, "\n"))
				}

				err = binary.Write(&keysbuffer, Endian, []byte(allkeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write key names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write key names to keysbuffer error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				return

			}

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		case istrue && ccnm == 3:

			var keysbuffer bytes.Buffer

			if DirExists(abs) {

				getkeys, err := FileKeys(abs, limit, offset)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate files in directory error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				filekeys := ""

				if hjson == "1" {
					jkeys, _ := json.Marshal(getkeys)
					filekeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
				} else {
					filekeys = fmt.Sprintf("%s\n", strings.Join(getkeys, "\n"))
				}

				err = binary.Write(&keysbuffer, Endian, []byte(filekeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write key names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write key names to keysbuffer error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		case istrue && ccnm == 4:

			var keysbuffer bytes.Buffer

			if FileExists(dbk) {

				db, err := BoltOpenRead(dbk, filemode, timeout, opentries, freelist)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}
				defer db.Close()

				getkeys, err := DBKeys(db, ibucket, limit, offset)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate keys of files in index db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate keys of files in index db bucket error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				dbkeys := ""

				if hjson == "1" {
					jkeys, _ := json.Marshal(getkeys)
					dbkeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
				} else {
					dbkeys = fmt.Sprintf("%s\n", strings.Join(getkeys, "\n"))
				}

				err = binary.Write(&keysbuffer, Endian, []byte(dbkeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write key names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write key names to keysbuffer error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				return

			}

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		}

		// Standart/Bolt Keys Info Iterator

		istrue, ccnm = StringOne(hinfo, hinfoall, hinfofiles, hinfoarchive)

		switch {

		case istrue && (ccnm == 1 || ccnm == 2):

			var keysbuffer bytes.Buffer

			uniq := true

			if ccnm == 2 {
				uniq = false
			}

			if DirExists(abs) && !FileExists(dbk) {

				getkeys, err := FileKeysInfo(abs, limit, offset)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate files in directory error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				filekeys := ""

				if hjson == "1" {
					jkeys, _ := json.Marshal(getkeys)
					filekeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
				} else {

					var sgetkeys []string

					for _, vs := range getkeys {
						sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(uint64(vs.Date), 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
					}

					filekeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

				}

				err = binary.Write(&keysbuffer, Endian, []byte(filekeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write key names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write key names to keysbuffer error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if FileExists(dbk) {

				db, err := BoltOpenRead(dbk, filemode, timeout, opentries, freelist)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}
				defer db.Close()

				getkeys, err := AllKeysInfo(db, ibucket, abs, uniq, limit, offset)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate keys of files in index db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate keys of files in index db bucket error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				allkeys := ""

				if hjson == "1" {
					jkeys, _ := json.Marshal(getkeys)
					allkeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
				} else {

					var sgetkeys []string

					for _, vs := range getkeys {
						sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(uint64(vs.Date), 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
					}

					allkeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

				}

				err = binary.Write(&keysbuffer, Endian, []byte(allkeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write key names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write key names to keysbuffer error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				return

			}

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		case istrue && ccnm == 3:

			var keysbuffer bytes.Buffer

			if DirExists(abs) {

				getkeys, err := FileKeysInfo(abs, limit, offset)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate files in directory error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				filekeys := ""

				if hjson == "1" {
					jkeys, _ := json.Marshal(getkeys)
					filekeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
				} else {

					var sgetkeys []string

					for _, vs := range getkeys {
						sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(uint64(vs.Date), 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
					}

					filekeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

				}

				err = binary.Write(&keysbuffer, Endian, []byte(filekeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write key names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write key names to keysbuffer error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		case istrue && ccnm == 4:

			var keysbuffer bytes.Buffer

			if FileExists(dbk) {

				db, err := BoltOpenRead(dbk, filemode, timeout, opentries, freelist)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}
				defer db.Close()

				getkeys, err := DBKeysInfo(db, ibucket, limit, offset)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate keys of files in index db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate keys of files in index db bucket error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				dbkeys := ""

				if hjson == "1" {
					jkeys, _ := json.Marshal(getkeys)
					dbkeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
				} else {

					var sgetkeys []string

					for _, vs := range getkeys {
						sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(uint64(vs.Date), 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
					}

					dbkeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

				}

				err = binary.Write(&keysbuffer, Endian, []byte(dbkeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write key names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write key names to keysbuffer error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				return

			}

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		}

		// Standart/Bolt Counter

		istrue, ccnm = StringOne(hcount, hcountall, hcountfiles, hcountarchive)

		switch {

		case istrue && (ccnm == 1 || ccnm == 2):

			uniq := true

			if ccnm == 2 {
				uniq = false
			}

			if DirExists(abs) && !FileExists(dbk) {

				filecount, err := FileCount(abs)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count files in directory error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				filecnt := ""

				if hjson == "1" {
					jcount, _ := json.Marshal(filecount)
					filecnt = fmt.Sprintf("{\n\t\"count\": %s\n}\n", string(jcount))
				} else {
					filecnt = fmt.Sprintf("%d\n", filecount)
				}

				_, err = ctx.Writef("%s", filecnt)
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if FileExists(dbk) {

				db, err := BoltOpenRead(dbk, filemode, timeout, opentries, freelist)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}
				defer db.Close()

				allkeyscount := 0

				switch uniq {

				case false:

					filecount, err := FileCount(abs)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t count files in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					keyscount, err := KeyCount(db, ibucket)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count keys of files in index db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t count keys of files in index db bucket error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						return

					}

					allkeyscount = keyscount + filecount

				case true:

					limit = 0
					offset = 0

					getkeys, err := AllKeys(db, ibucket, abs, uniq, limit, offset)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate keys of files in index db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t iterate keys of files in index db bucket error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						return

					}

					//					allkeys := fmt.Sprintf("%s", strings.Join(getkeys, "\n"))
					allkeys := strings.Join(getkeys, "\n")
					scanner := bufio.NewScanner(strings.NewReader(allkeys))

					for scanner.Scan() {
						allkeyscount++
					}

					err = scanner.Err()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t scan count strings of keys error | DB [%s] | %v", vhost, ip, dbk, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t scan count strings of keys error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						return

					}

				}

				allkeyscnt := ""

				if hjson == "1" {
					jcount, _ := json.Marshal(allkeyscount)
					allkeyscnt = fmt.Sprintf("{\n\t\"count\": %s\n}\n", string(jcount))
				} else {
					allkeyscnt = fmt.Sprintf("%d\n", allkeyscount)
				}

				_, err = ctx.Writef("%s", allkeyscnt)
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				return

			}

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		case istrue && ccnm == 3:

			if DirExists(abs) {

				filecount, err := FileCount(abs)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count files in directory error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				filecnt := ""

				if hjson == "1" {
					jcount, _ := json.Marshal(filecount)
					filecnt = fmt.Sprintf("{\n\t\"count\": %s\n}\n", string(jcount))
				} else {
					filecnt = fmt.Sprintf("%d\n", filecount)
				}

				_, err = ctx.Writef("%s", filecnt)
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		case istrue && ccnm == 4:

			if FileExists(dbk) {

				db, err := BoltOpenRead(dbk, filemode, timeout, opentries, freelist)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}
				defer db.Close()

				keyscount, err := KeyCount(db, ibucket)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count keys of files in index db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count keys of files in index db bucket error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				keyscnt := ""

				if hjson == "1" {
					jcount, _ := json.Marshal(keyscount)
					keyscnt = fmt.Sprintf("{\n\t\"count\": %s\n}\n", string(jcount))
				} else {
					keyscnt = fmt.Sprintf("%d\n", keyscount)
				}

				_, err = ctx.Writef("%s", keyscnt)
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		}

		if DirExists(abs) {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Forbidden | Path [%s]", vhost, ip, abs)
			}

			return

		}

		// Standart Reader

		if FileExists(abs) && fromarchive != "1" {

			infile, err := os.Stat(abs)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t stat file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t stat file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t open file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}
			defer pfile.Close()

			contbuffer := make([]byte, 512)

			csizebuffer, err := pfile.Read(contbuffer)
			if err != nil && err != io.EOF {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | csizebuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				err = pfile.Close()
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close during read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						ctx.StatusCode(iris.StatusInternalServerError)
						_, err = ctx.WriteString("[ERRO] Close during read file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] csizebuffer read file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			conttype, err := ContentType(file, size, contbuffer, csizebuffer)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | contbuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				err = pfile.Close()
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close during contbuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Close during contbuffer read file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] contbuffer read file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			etag := fmt.Sprintf("%x-%x", tmst, size)
			scctrl := fmt.Sprintf("max-age=%d", cctrl)

			ctx.Header("Content-Type", conttype)
			ctx.Header("Content-Length", hsize)
			ctx.Header("Last-Modified", hmodt)
			// ctx.Header("Transfer-Encoding", "chunked")
			// ctx.Header("Connection", "keep-alive")
			ctx.Header("ETag", etag)
			ctx.Header("Cache-Control", scctrl)
			ctx.Header("Accept-Ranges", "bytes")

			if strings.Contains(ctx.GetHeader("Accept-Encoding"), "gzip") && (strings.Contains(conttype, "x-compressed") || strings.Contains(conttype, "gzip")) {
				ctx.Header("Content-Encoding", "gzip")
			}

			if headorigin != "" {
				ctx.Header("Access-Control-Allow-Origin", headorigin)
			}

			if xframe != "" {
				ctx.Header("X-Frame-Options", xframe)
			}

			if ifnm == etag || ifms == hmodt {

				err = pfile.Close()
				if err != nil {
					ctx.StatusCode(iris.StatusNotModified)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Close after etag/modtime file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
					return
				}

				ctx.StatusCode(iris.StatusNotModified)
				return

			}

			if method == "HEAD" || method == "OPTIONS" {

				err = pfile.Close()
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Close after head/options file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
					return
				}

				if method == "OPTIONS" && options != "" {
					ctx.Header("Access-Control-Allow-Methods", options)
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

				reqr, err := ParseByRange(rngs, size)
				if err != nil {

					ctx.StatusCode(iris.StatusRequestedRangeNotSatisfiable)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 416 | Bad Range | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Invalid range error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 416 | Can`t seek to position [%d] error | File [%s] | Path [%s] | %v", vhost, ip, rstart, file, abs, err)
					}

					err = pfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close during seek file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close during seek file error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if debugmode {

						_, err = ctx.Writef("[ERRO] Can`t seek to position [%d] error\n", rstart)
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
							// getLogger.Infof("| sizebuffer end of file | File [%s] | Path [%s] | %v", file, abs, err)
							break
						}

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | sizebuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						err = pfile.Close()
						if err != nil {

							ctx.StatusCode(iris.StatusInternalServerError)
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close during read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

							if debugmode {

								_, err = ctx.WriteString("[ERRO] Close during read file error\n")
								if err != nil {
									getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
								}

							}

							return

						}

						if debugmode {

							_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					_, err = ctx.Write(readbuffer[:sizebuffer])
					if err != nil {

						if log4xx {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

						err = pfile.Close()
						if err != nil {

							ctx.StatusCode(iris.StatusInternalServerError)
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close during readbuffer send file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

							if debugmode {

								_, err = ctx.WriteString("[ERRO] Close during readbuffer send file error\n")
								if err != nil {
									getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Close after send range of file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
					return
				}

				return

			}

			// Standart File Reader

			_, err = pfile.Seek(0, 0)
			if err != nil {

				ctx.StatusCode(iris.StatusRequestedRangeNotSatisfiable)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 416 | Can`t seek to position 0 error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
				}

				err = pfile.Close()
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close during seek file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Close during seek file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t seek to position 0 error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
						// getLogger.Infof("| sizebuffer end of file | File [%s] | Path [%s] | %v", file, abs, err)
						break
					}

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | sizebuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					err = pfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close during read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close during read file error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				_, err = ctx.Write(readbuffer[:sizebuffer])
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

					err = pfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close during readbuffer send file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close during readbuffer send file error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Close after send file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
				return
			}

			return

		}

		// Bolt Reader

		if dir == "/" && dbn == "/" {
			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		}

		if !FileExists(dbf) {
			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		}

		db, err := BoltOpenRead(dbf, filemode, timeout, opentries, freelist)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}
		defer db.Close()

		keyexists, err := KeyExists(db, ibucket, file)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t check key of file in index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t check key of file in index db bucket error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			db.Close()
			return

		}

		if gzstatic {

			gzkeyexists := ""
			gzabs := fmt.Sprintf("%s%s/%s.gz", base, dir, file)
			gzfile := fmt.Sprintf("%s.gz", file)

			gzkeyexists, err = KeyExists(db, ibucket, gzfile)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t check key of file in index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, gzfile, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t check key of file in index db bucket error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				return

			}

			if gzkeyexists != "" {
				keyexists = gzkeyexists
				abs = gzabs
				file = gzfile
			}

		}

		if keyexists == "" {
			ctx.StatusCode(iris.StatusNotFound)
			db.Close()

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			return

		}

		bucket = keyexists

		// Header Bolt Reader

		var pheader []byte

		err = db.View(func(tx *bolt.Tx) error {

			verr := errors.New("bucket not exists")

			b := tx.Bucket([]byte(bucket))
			if b != nil {
				pheader = b.GetLimit([]byte(file), uint32(544))
				return nil
			} else {
				return verr
			}

		})
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t get data header by key from db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t get data header by key from db error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			db.Close()
			return

		}

		preadheader := bytes.NewReader(pheader)

		var readhead Header

		headbuffer := make([]byte, 32)

		hsizebuffer, err := preadheader.Read(headbuffer)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Read header data from db error | File [%s] | DB [%s] | Header Buffer [%p] | %v", vhost, ip, file, dbf, headbuffer, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Read header data from db error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			db.Close()
			return

		}

		hread := bytes.NewReader(headbuffer[:hsizebuffer])

		err = binary.Read(hread, Endian, &readhead)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Read binary header data from db error | File [%s] | DB [%s] | Header Buffer [%p] | %v", vhost, ip, file, dbf, hread, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Read binary header data from db error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			db.Close()
			return

		}

		size := int64(readhead.Size)
		hsize := strconv.FormatUint(readhead.Size, 10)

		tmst := int64(readhead.Date)
		modt := time.Unix(tmst, 0)
		hmodt := modt.Format(http.TimeFormat)

		crc := readhead.Crcs

		contbuffer := make([]byte, 512)

		csizebuffer, err := preadheader.Read(contbuffer)
		if err != nil && err != io.EOF {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | csizebuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] csizebuffer read file error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			db.Close()
			return

		}

		conttype, err := ContentType(file, size, contbuffer, csizebuffer)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | contbuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] contbuffer read file error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
		// ctx.Header("Transfer-Encoding", "chunked")
		// ctx.Header("Connection", "keep-alive")
		ctx.Header("ETag", etag)
		ctx.Header("Cache-Control", scctrl)
		ctx.Header("Accept-Ranges", "bytes")

		if strings.Contains(ctx.GetHeader("Accept-Encoding"), "gzip") && (strings.Contains(conttype, "x-compressed") || strings.Contains(conttype, "gzip")) {
			ctx.Header("Content-Encoding", "gzip")
		}

		if headorigin != "" {
			ctx.Header("Access-Control-Allow-Origin", headorigin)
		}

		if xframe != "" {
			ctx.Header("X-Frame-Options", xframe)
		}

		if ifnm == etag || ifms == hmodt {
			ctx.StatusCode(iris.StatusNotModified)
			db.Close()
			return
		}

		if method == "HEAD" || method == "OPTIONS" {

			if method == "OPTIONS" && options != "" {
				ctx.Header("Access-Control-Allow-Methods", options)
			}

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

			reqr, err := ParseByRange(rngs, size)
			if err != nil {

				ctx.StatusCode(iris.StatusRequestedRangeNotSatisfiable)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 416 | Bad Range | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Invalid range error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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

				verr := errors.New("bucket not exists")

				b := tx.Bucket([]byte(bucket))
				if b != nil {
					pdata = b.GetRange([]byte(file), uint32(rstart+32), uint32(rlength))
					return nil
				} else {
					return verr
				}

			})
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t get data by key from db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t get data by key from db error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
				case rlength >= lowbuffer && rlength < medbuffer:
					readbuffer = make([]byte, lowbuffer)
				case rlength >= bigbuffer:
					readbuffer = make([]byte, medbuffer)
				}

				sizebuffer, err := pread.Read(readbuffer)
				if err != nil {
					if err == io.EOF {
						// getLogger.Infof("| sizebuffer end of file | File [%s] | DB [%s] | %v", file, dbf, err)
						break
					}

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | sizebuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Write(readbuffer[:sizebuffer])
				if err != nil {

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

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

			verr := errors.New("bucket not exists")

			b := tx.Bucket([]byte(bucket))
			if b != nil {
				pdata = b.GetOffset([]byte(file), uint32(32))
				return nil
			} else {
				return verr
			}

		})
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t get data by key from db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t get data by key from db error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t read data to fullbuffer error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t read data to fullbuffer error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				return

			}

			tbl := crc32.MakeTable(0xEDB88320)
			rcrc := crc32.Checksum(fullbuffer.Bytes(), tbl)

			if rcrc != crc {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | CRC read file error | File [%s] | DB [%s] | Have CRC [%v] | Awaiting CRC [%v]", vhost, ip, file, dbf, rcrc, crc)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] CRC read file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				return

			}

			_, err = ctx.Write(fullbuffer.Bytes())
			if err != nil {

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

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
			case rlength >= lowbuffer && rlength < medbuffer:
				readbuffer = make([]byte, lowbuffer)
			case rlength >= bigbuffer:
				readbuffer = make([]byte, medbuffer)
			}

			sizebuffer, err := pread.Read(readbuffer)
			if err != nil {
				if err == io.EOF {
					// getLogger.Infof("| sizebuffer end of file | File [%s] | DB [%s] | %v", file, dbf, err)
					break
				}

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | sizebuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				db.Close()
				return

			}

			_, err = ctx.Write(readbuffer[:sizebuffer])
			if err != nil {

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

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
