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
	"bufio"
	"bytes"
	"encoding/binary"
	// "encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coocood/freecache"
	"github.com/eltaline/bolt"
	"github.com/eltaline/nutsdb"
	"github.com/kataras/iris/v12"
	"golang.org/x/crypto/blake2b"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Get

// ZDGet : GET/HEAD/OPTIONS methods
func ZDGet(cache *freecache.Cache, ndb *nutsdb.DB, wg *sync.WaitGroup) iris.Handler {
	return func(ctx iris.Context) {
		defer wg.Done()

		var err error

		// Wait Group

		wg.Add(1)

		// Loggers

		getLogger, getlogfile := GetLogger()
		defer getlogfile.Close()

		// Shutdown

		if shutdown {
			ctx.StatusCode(iris.StatusInternalServerError)
			// _, err = ctx.WriteString("[ERRO] Shutdown wZD server in progress\n")
			// if err != nil {
			//	getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client| %v", vhost, ip, err)
			// }
			return
		}

		// Headers

		ip := ctx.RemoteAddr()
		cip := net.ParseIP(ip)
		vhost := strings.Split(ctx.Host(), ":")[0]

		uri := ctx.Path()
		furi := ctx.FullRequestURI()
		params := ctx.URLParams()
		method := ctx.Method()

		ifnm := ctx.GetHeader("If-None-Match")
		ifms := ctx.GetHeader("If-Modified-Since")

		fromfile := ctx.GetHeader("FromFile")
		fromarchive := ctx.GetHeader("FromArchive")

		hsea := ctx.GetHeader("Sea")

		badhost := true
		badip := true

		base := "/notfound"

		options := ""
		headorigin := ""
		xframe := ""

		getbolt := false
		getkeys := false
		getinfo := false
		getsearch := false
		getrecursive := false
		getjoin := false
		getvalue := false
		getcount := false
		getcache := false

		searchthreads := 4
		searchtimeout := 10

		readintegrity := true

		opentries := 5
		locktimeout := 5

		vmaxsize := int64(1024)

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

				base = filepath.Clean(Server.ROOT)

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
				getsearch = Server.GETSEARCH
				getrecursive = Server.GETRECURSIVE
				getjoin = Server.GETJOIN
				getvalue = Server.GETVALUE
				getcount = Server.GETCOUNT
				getcache = Server.GETCACHE

				searchthreads = Server.SEARCHTHREADS
				searchtimeout = Server.SEARCHTIMEOUT

				readintegrity = Server.READINTEGRITY

				opentries = Server.OPENTRIES
				locktimeout = Server.LOCKTIMEOUT

				vmaxsize = Server.VMAXSIZE

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

				_, err = ctx.Writef("[ERRO] Not found configured virtual host | Virtual Host [%s]\n", vhost)
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

				_, err = ctx.Writef("[ERRO] Not found allowed ip | Virtual Host [%s]\n", vhost)
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if !args {

			if len(params) != 0 {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The query arguments is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] The query arguments is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

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

					_, err = ctx.WriteString("[ERRO] The direct bolt request is not allowed during GET request\n")
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

				_, err = ctx.WriteString("[ERRO] Restricted to download .crcbolt file error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

		}

		abs := filepath.Clean(base + dir + "/" + file)
		ddir := filepath.Clean(base + dir)

		gzabs := filepath.Clean(base + dir + "/" + file + ".gz")
		gzfile := file + ".gz"

		dbn := filepath.Base(dir)
		dbf := filepath.Clean(base + dir + "/" + dbn + ".bolt")

		if gzstatic && FileExists(gzabs) {
			abs = gzabs
			file = gzfile
		}

		bucket := ""
		ibucket := "index"

		timeout := time.Duration(locktimeout) * time.Second

		if method == "GET" && hsea == "1" && search {

			ups, _ := url.Parse(furi)
			furi = ups.Scheme + "://" + ups.Host

			prefix := ""
			expression := ""
			recursive := 0
			stopfirst := uint8(0)
			withurl := false
			withjoin := make(map[string]int)
			withvalue := false

			minsize := uint64(0)
			maxsize := uint64(0)

			minstmp := uint64(0)
			maxstmp := uint64(0)

			offset := -1
			limit := -1

			msort := uint8(0)

			expire := -1
			skipcache := false

			// sbucket := "size"
			// tbucket := "time"

			hkeys := ctx.GetHeader("Keys")
			hkeysfiles := ctx.GetHeader("KeysFiles")
			hkeysarchives := ctx.GetHeader("KeysArchives")

			hinfo := ctx.GetHeader("KeysInfo")
			hinfofiles := ctx.GetHeader("KeysInfoFiles")
			hinfoarchives := ctx.GetHeader("KeysInfoArchives")

			hsearch := ctx.GetHeader("KeysSearch")
			hsearchfiles := ctx.GetHeader("KeysSearchFiles")
			hsearcharchives := ctx.GetHeader("KeysSearchArchives")

			hcount := ctx.GetHeader("KeysCount")
			hcountfiles := ctx.GetHeader("KeysCountFiles")
			hcountarchives := ctx.GetHeader("KeysCountArchives")

			hprefix := ctx.GetHeader("Prefix")
			hexpression := ctx.GetHeader("Expression")
			hrecursive := ctx.GetHeader("Recursive")
			hstopfirst := ctx.GetHeader("StopFirst")

			hminsize := ctx.GetHeader("MinSize")
			hmaxsize := ctx.GetHeader("MaxSize")

			hminstmp := ctx.GetHeader("MinStmp")
			hmaxstmp := ctx.GetHeader("MaxStmp")

			hwithurl := ctx.GetHeader("WithUrl")
			hwithjoin := ctx.GetHeader("WithJoin")
			hwithvalue := ctx.GetHeader("WithValue")

			hoffset := ctx.GetHeader("Offset")
			hlimit := ctx.GetHeader("Limit")

			hsort := ctx.GetHeader("Sort")

			hexpire := ctx.GetHeader("Expire")
			hskipcache := ctx.GetHeader("SkipCache")

			hjson := ctx.GetHeader("JSON")

			if !getkeys && (hkeys != "" || hkeysfiles != "" || hkeysarchives != "" || hexpression != "" || hprefix != "") {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The keys request is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] The keys request is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if !getinfo && (hinfo != "" || hinfofiles != "" || hinfoarchives != "" || hexpression != "" || hprefix != "") {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The keys info request is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] The keys info request is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if !getsearch && (hsearch != "" || hsearchfiles != "" || hsearcharchives != "" || hexpression != "" || hprefix != "") {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The keys search request is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] The keys search request is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if !getrecursive && hrecursive != "" {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The keys recursive request is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] The keys recursive request is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if !getjoin && hwithjoin != "" {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The keys with join request is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] The keys with join request is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if !getvalue && hwithvalue != "" {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The keys with value request is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] The keys with value request is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if !getcount && (hcount != "" || hcountfiles != "" || hcountarchives != "") {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The count request is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] The count request is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if !getcache && hexpire != "" {

				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The expire request is not allowed during GET request", vhost, ip)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] The expire request is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			// Check Additional Headers for GET keys* requests

			if hprefix != "" {
				prefix = hprefix
			}

			if hexpression != "" {
				expression = hexpression
			} else {
				expression = "(.+)"
			}

			if hrecursive != "" {

				if hwithjoin != "" {

					ctx.StatusCode(iris.StatusConflict)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Recursive header conflicts with WithJoin header error during GET keys* request", vhost, ip)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Recursive header conflicts with WithJoin header error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				recursive64, err := strconv.ParseInt(hrecursive, 10, 32)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Recursive int error during GET keys* request | Recursive [%s] | %v", vhost, ip, hrecursive, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Recursive int error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				recursive = int(recursive64)

			}

			if hstopfirst != "" {

				stopfirst64, err := strconv.ParseUint(hstopfirst, 10, 8)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | StopFirst uint error during GET keys* request | StopFirst [%s] | %v", vhost, ip, hstopfirst, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] StopFirst uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				if stopfirst64 >= 1 {
					stopfirst = 1
				} else {
					stopfirst = uint8(stopfirst64)
				}

			}

			if hminsize != "" {

				minsize, err = strconv.ParseUint(hminsize, 10, 64)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | MinSize uint error during GET keys* request | MinSize [%s] | %v", vhost, ip, hminsize, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] MinSize uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

			}

			if hmaxsize != "" {

				maxsize, err = strconv.ParseUint(hmaxsize, 10, 64)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | MaxSize uint error during GET keys* request | MaxSize [%s] | %v", vhost, ip, hmaxsize, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] MaxSize uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

			}

			if hminstmp != "" {

				minstmp, err = strconv.ParseUint(hminstmp, 10, 64)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | MinStmp uint error during GET keys* request | MinStmp [%s] | %v", vhost, ip, hminstmp, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] MinStmp uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

			}

			if hmaxstmp != "" {

				maxstmp, err = strconv.ParseUint(hmaxstmp, 10, 64)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | MaxStmp uint error during GET keys* request | MaxStmp [%s] | %v", vhost, ip, hmaxstmp, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] MaxStmp uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

			}

			if hwithurl != "" {

				withurl64, err := strconv.ParseUint(hwithurl, 10, 8)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | WithUrl uint error during GET keys* request | WithUrl [%s] | %v", vhost, ip, hwithurl, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] WithUrl uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				if withurl64 >= 1 {
					withurl = true
				}

			}

			if hwithjoin != "" {

				if hrecursive != "" {

					ctx.StatusCode(iris.StatusConflict)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | WithJoin header conflicts with Recursive header error during GET keys* request", vhost, ip)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] WithJoin header conflicts with Recursive header error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				abs = base

				jpaths := rgxjoin.FindAllStringSubmatch(hwithjoin, -1)

				for _, kval := range jpaths {
					kdir := filepath.Clean(base + "/" + strings.TrimSpace(kval[1]))

					if !DirExists(kdir) {

						ctx.StatusCode(iris.StatusNotFound)

						if log4xx {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, kdir)
						}

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t find join directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					rval, err := strconv.ParseInt(kval[2], 10, 32)
					if err != nil {

						ctx.StatusCode(iris.StatusBadRequest)

						if log4xx {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Recursive int error during GET keys* request | WithJoin [%s] | %v", vhost, ip, hwithjoin, err)
						}

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Recursive int error during GET keys* request\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					withjoin[kdir] = int(rval)

				}

			}

			if hwithvalue != "" {

				withvalue64, err := strconv.ParseUint(hwithvalue, 10, 8)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | WithValue uint error during GET keys* request | WithValue [%s] | %v", vhost, ip, hwithvalue, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] WithValue uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				if withvalue64 >= 1 {
					withvalue = true
				}

			}

			if hoffset != "" {

				offset64, err := strconv.ParseInt(hoffset, 10, 32)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Offset int error during GET keys* request | Offset [%s] | %v", vhost, ip, hoffset, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Offset int error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				offset = int(offset64)

			}

			if hlimit != "" {

				limit64, err := strconv.ParseInt(hlimit, 10, 32)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Limit int error during GET keys* request | Limit [%s] | %v", vhost, ip, hlimit, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Limit int error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				limit = int(limit64)

			}

			if hsort != "" {

				switch {
				case hsort == "0":
					msort = uint8(0)
				case hsort == "1":
					msort = uint8(1)
				default:
					msort = uint8(0)
				}

			}

			if hexpire != "" {

				expire64, err := strconv.ParseUint(hexpire, 10, 32)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Expire uint error during GET keys* request | Expire [%s] | %v", vhost, ip, hexpire, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Expire uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				expire = int(expire64)

			}

			if hskipcache != "" {

				skipcache64, err := strconv.ParseUint(hskipcache, 10, 8)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | SkipCache uint error during GET keys* request | SkipCache [%s] | %v", vhost, ip, hskipcache, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] SkipCache uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				if skipcache64 >= 1 {
					skipcache = true
				}

			}

			// Cache

			var vckey []byte
			var vchash []byte = nil
			var vcerr string = "0"
			var errmsg string = "none"

			if search && getcache {

				vckey = []byte("host:" + vhost + ";path:" + abs + ";params:" + fmt.Sprintf("%s", params) + ";hk:" + hkeys + ";hkf:" + hkeysfiles + ";hka:" + hkeysarchives +
					";hi:" + hinfo + ";hif:" + hinfofiles + ";hia:" + hinfoarchives +
					";hs:" + hsearch + ";hsf:" + hsearchfiles + ";hsa:" + hsearcharchives +
					";hc:" + hcount + ";hcf:" + hcountfiles + ";hca:" + hcountarchives +
					";hp:" + hprefix + ";he:" + hexpression + ";hr:" + hrecursive + ";ht:" + hstopfirst +
					";hmix:" + hminsize + ";hmax:" + hmaxsize + ";hsix:" + hminstmp + ";hsax:" + hmaxstmp +
					";hwrl:" + hwithurl + ";hwjn:" + hwithjoin + ";hwvl:" + hwithvalue +
					";hoff:" + hoffset + ";hlim:" + hlimit + ";hsrt:" + hsort + ";hjsn:" + hjson)

				vcblk := blake2b.Sum256(vckey)
				vchash = vcblk[:]
				// vchash = hex.EncodeToString(vcblk[:])

				if !skipcache {

					vcget, err := cache.Get(vchash)
					if err == nil {

						conttype := http.DetectContentType(vcget)

						hsize := fmt.Sprintf("%d", len(vcget))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "1")
						ctx.Header("Errcache", vcerr)
						ctx.Header("Errmsg", errmsg)

						_, err = ctx.Write(vcget)
						if err != nil {

							if log4xx {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

				}

			}

			// Standart/Bolt Keys Iterator

			istrue, ccnm := StringOne(hkeys, hkeysfiles, hkeysarchives)

			switch {

			case istrue && ccnm == 1:

				if DirExists(abs) {

					getkeys, err := AllKeys(ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate files and keys in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t iterate files and keys in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if len(getkeys) != 0 {

						allkeys := ""

						if hjson == "1" {
							jkeys, _ := json.Marshal(getkeys)
							allkeys = fmt.Sprintf("{\"keys\": %s}", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							allkeys = strings.TrimSpace(strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n"))

						}

						rbytes := []byte(allkeys)

						conttype := http.DetectContentType(rbytes)

						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if search && getcache && expire >= 0 {

							err = cache.Set(vchash, rbytes, expire)
							if err != nil {
								vcerr = "1"
								errmsg = fmt.Sprintf("%v", err)
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
							}

						}

						ctx.Header("Errcache", vcerr)
						ctx.Header("Errmsg", errmsg)

						_, err = ctx.Write(rbytes)
						if err != nil {

							if log4xx {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

					}

					return

				}

				ctx.StatusCode(iris.StatusNotFound)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			case istrue && ccnm == 2:

				if DirExists(abs) {

					getkeys, _, _, err := FileKeys(ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate files in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t iterate files in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if len(getkeys) != 0 {

						filekeys := ""

						if hjson == "1" {
							jkeys, _ := json.Marshal(getkeys)
							filekeys = fmt.Sprintf("{\"keys\": %s}", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							filekeys = strings.TrimSpace(strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n"))

						}

						rbytes := []byte(filekeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if search && getcache && expire >= 0 {

							err = cache.Set(vchash, rbytes, expire)
							if err != nil {
								vcerr = "1"
								errmsg = fmt.Sprintf("%v", err)
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
							}

						}

						ctx.Header("Errcache", vcerr)
						ctx.Header("Errmsg", errmsg)

						_, err = ctx.Write(rbytes)
						if err != nil {

							if log4xx {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

					}

					return

				}

				ctx.StatusCode(iris.StatusNotFound)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			case istrue && ccnm == 3:

				if DirExists(abs) {

					getkeys, err := DBKeys(ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate keys in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t iterate keys in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if len(getkeys) != 0 {

						dbkeys := ""

						if hjson == "1" {
							jkeys, _ := json.Marshal(getkeys)
							dbkeys = fmt.Sprintf("{\"keys\": %s}", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							dbkeys = strings.TrimSpace(strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n"))

						}

						rbytes := []byte(dbkeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if search && getcache && expire >= 0 {

							err = cache.Set(vchash, rbytes, expire)
							if err != nil {
								vcerr = "1"
								errmsg = fmt.Sprintf("%v", err)
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
							}

						}

						ctx.Header("Errcache", vcerr)
						ctx.Header("Errmsg", errmsg)

						_, err = ctx.Write(rbytes)
						if err != nil {

							if log4xx {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

					}

					return

				}

				ctx.StatusCode(iris.StatusNotFound)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			// Standart/Bolt Keys Info Iterator

			istrue, ccnm = StringOne(hinfo, hinfofiles, hinfoarchives)

			switch {

			case istrue && ccnm == 1:

				if DirExists(abs) {

					getkeys, err := AllKeysInfo(ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate files and keys in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t iterate files and keys in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if len(getkeys) != 0 {

						allkeys := ""

						if hjson == "1" {
							jkeys, _ := json.Marshal(getkeys)
							allkeys = fmt.Sprintf("{\"keys\": %s}", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							allkeys = strings.TrimSpace(strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n"))

						}

						rbytes := []byte(allkeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if search && getcache && expire >= 0 {

							err = cache.Set(vchash, rbytes, expire)
							if err != nil {
								vcerr = "1"
								errmsg = fmt.Sprintf("%v", err)
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
							}

						}

						ctx.Header("Errcache", vcerr)
						ctx.Header("Errmsg", errmsg)

						_, err = ctx.Write(rbytes)
						if err != nil {

							if log4xx {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

					}

					return

				}

				ctx.StatusCode(iris.StatusNotFound)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			case istrue && ccnm == 2:

				if DirExists(abs) {

					getkeys, _, _, err := FileKeysInfo(ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate files in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t iterate files in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if len(getkeys) != 0 {

						filekeys := ""

						if hjson == "1" {
							jkeys, _ := json.Marshal(getkeys)
							filekeys = fmt.Sprintf("{\"keys\": %s}", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							filekeys = strings.TrimSpace(strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n"))

						}

						rbytes := []byte(filekeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if search && getcache && expire >= 0 {

							err = cache.Set(vchash, rbytes, expire)
							if err != nil {
								vcerr = "1"
								errmsg = fmt.Sprintf("%v", err)
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
							}

						}

						ctx.Header("Errcache", vcerr)
						ctx.Header("Errmsg", errmsg)

						_, err = ctx.Write(rbytes)
						if err != nil {

							if log4xx {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

					}

					return

				}

				ctx.StatusCode(iris.StatusNotFound)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			case istrue && ccnm == 3:

				if DirExists(abs) {

					getkeys, err := DBKeysInfo(ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t iterate keys directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t iterate keys in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if len(getkeys) != 0 {

						dbkeys := ""

						if hjson == "1" {
							jkeys, _ := json.Marshal(getkeys)
							dbkeys = fmt.Sprintf("{\"keys\": %s}", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							dbkeys = strings.TrimSpace(strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n"))

						}

						rbytes := []byte(dbkeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if search && getcache && expire >= 0 {

							err = cache.Set(vchash, rbytes, expire)
							if err != nil {
								vcerr = "1"
								errmsg = fmt.Sprintf("%v", err)
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
							}

						}

						ctx.Header("Errcache", vcerr)
						ctx.Header("Errmsg", errmsg)

						_, err = ctx.Write(rbytes)
						if err != nil {

							if log4xx {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

					}

					return

				}

				ctx.StatusCode(iris.StatusNotFound)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			// Standart/Bolt Keys Search

			istrue, ccnm = StringOne(hsearch, hsearchfiles, hsearcharchives)

			switch {

			case istrue && ccnm == 1:

				if DirExists(abs) {

					getkeys, err := AllKeysSearch(filemode, timeout, opentries, freelist, ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, withvalue, vmaxsize, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t search files and keys in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t search files and keys in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if len(getkeys) != 0 {

						allkeys := ""

						if hjson == "1" {
							jkeys, _ := json.Marshal(getkeys)
							allkeys = fmt.Sprintf("{\"keys\": %s}", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							allkeys = strings.TrimSpace(strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n"))

						}

						rbytes := []byte(allkeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if search && getcache && expire >= 0 {

							err = cache.Set(vchash, rbytes, expire)
							if err != nil {
								vcerr = "1"
								errmsg = fmt.Sprintf("%v", err)
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
							}

						}

						ctx.Header("Errcache", vcerr)
						ctx.Header("Errmsg", errmsg)

						_, err = ctx.Write(rbytes)
						if err != nil {

							if log4xx {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

					}

					return

				}

				ctx.StatusCode(iris.StatusNotFound)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			case istrue && ccnm == 2:

				if DirExists(abs) {

					getkeys, _, _, err := FileKeysSearch(ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, withvalue, vmaxsize, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t search files in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t search files in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if len(getkeys) != 0 {

						filekeys := ""

						if hjson == "1" {
							jkeys, _ := json.Marshal(getkeys)
							filekeys = fmt.Sprintf("{\"keys\": %s}", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							filekeys = strings.TrimSpace(strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n"))

						}

						rbytes := []byte(filekeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if search && getcache && expire >= 0 {

							err = cache.Set(vchash, rbytes, expire)
							if err != nil {
								vcerr = "1"
								errmsg = fmt.Sprintf("%v", err)
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
							}

						}

						ctx.Header("Errcache", vcerr)
						ctx.Header("Errmsg", errmsg)

						_, err = ctx.Write(rbytes)
						if err != nil {

							if log4xx {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

					}

					return

				}

				ctx.StatusCode(iris.StatusNotFound)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			case istrue && ccnm == 3:

				if DirExists(abs) {

					getkeys, err := DBKeysSearch(filemode, timeout, opentries, freelist, ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, withvalue, vmaxsize, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t search keys in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t search keys directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if len(getkeys) != 0 {

						dbkeys := ""

						if hjson == "1" {
							jkeys, _ := json.Marshal(getkeys)
							dbkeys = fmt.Sprintf("{\"keys\": %s}", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							dbkeys = strings.TrimSpace(strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n"))

						}

						rbytes := []byte(dbkeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if search && getcache && expire >= 0 {

							err = cache.Set(vchash, rbytes, expire)
							if err != nil {
								vcerr = "1"
								errmsg = fmt.Sprintf("%v", err)
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
							}

						}

						ctx.Header("Errcache", vcerr)
						ctx.Header("Errmsg", errmsg)

						_, err = ctx.Write(rbytes)
						if err != nil {

							if log4xx {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

					}

					return

				}

				ctx.StatusCode(iris.StatusNotFound)

				if log4xx {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			// Standart/Bolt Counter

			istrue, ccnm = StringOne(hcount, hcountfiles, hcountarchives)

			switch {

			case istrue && ccnm == 1:

				limit = -1

				if DirExists(abs) {

					allkeyscount := 0

					getkeys, err := AllKeys(ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count files and keys in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t count files and keys in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					var sgetkeys []string

					for _, vs := range getkeys {
						sgetkeys = append(sgetkeys, vs.Key)
					}

					allkeys := strings.Join(sgetkeys, "\n")
					scanner := bufio.NewScanner(strings.NewReader(allkeys))

					for scanner.Scan() {
						allkeyscount++
					}

					err = scanner.Err()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t scan count strings of files and keys error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t scan count strings of files and keys error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					allkeyscnt := ""

					if hjson == "1" {
						jcount, _ := json.Marshal(allkeyscount)
						allkeyscnt = fmt.Sprintf("{\"count\": %s}", string(jcount))
					} else {
						allkeyscnt = fmt.Sprintf("%d", allkeyscount)
					}

					rbytes := []byte(allkeyscnt)

					conttype := http.DetectContentType(rbytes)
					hsize := fmt.Sprintf("%d", len(rbytes))
					scctrl := fmt.Sprintf("max-age=%d", cctrl)

					ctx.Header("Content-Type", conttype)
					ctx.Header("Content-Length", hsize)
					ctx.Header("Cache-Control", scctrl)

					ctx.Header("Hitcache", "0")

					if search && getcache && expire >= 0 {

						err = cache.Set(vchash, rbytes, expire)
						if err != nil {
							vcerr = "1"
							errmsg = fmt.Sprintf("%v", err)
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
						}

					}

					ctx.Header("Errcache", vcerr)
					ctx.Header("Errmsg", errmsg)

					_, err = ctx.Write(rbytes)
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

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			case istrue && ccnm == 2:

				filekeyscount := 0

				limit = -1

				if DirExists(abs) {

					getkeys, _, _, err := FileKeys(ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count files in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t count files in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					var sgetkeys []string

					for _, vs := range getkeys {
						sgetkeys = append(sgetkeys, vs.Key)
					}

					filekeys := strings.Join(sgetkeys, "\n")
					scanner := bufio.NewScanner(strings.NewReader(filekeys))

					for scanner.Scan() {
						filekeyscount++
					}

					err = scanner.Err()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t scan count strings of files error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t scan count strings of files error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					filekeyscnt := ""

					if hjson == "1" {
						jcount, _ := json.Marshal(filekeyscount)
						filekeyscnt = fmt.Sprintf("{\"count\": %s}", string(jcount))
					} else {
						filekeyscnt = fmt.Sprintf("%d", filekeyscount)
					}

					rbytes := []byte(filekeyscnt)

					conttype := http.DetectContentType(rbytes)
					hsize := fmt.Sprintf("%d", len(rbytes))
					scctrl := fmt.Sprintf("max-age=%d", cctrl)

					ctx.Header("Content-Type", conttype)
					ctx.Header("Content-Length", hsize)
					ctx.Header("Cache-Control", scctrl)

					ctx.Header("Hitcache", "0")

					if search && getcache && expire >= 0 {

						err = cache.Set(vchash, rbytes, expire)
						if err != nil {
							vcerr = "1"
							errmsg = fmt.Sprintf("%v", err)
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
						}

					}

					ctx.Header("Errcache", vcerr)
					ctx.Header("Errmsg", errmsg)

					_, err = ctx.Write(rbytes)
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

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			case istrue && ccnm == 3:

				dbkeyscount := 0

				limit = -1

				if DirExists(abs) {

					getkeys, err := DBKeys(ndb, base, abs, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withjoin, searchthreads, searchtimeout)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count keys in directory error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t count keys in directory error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					var sgetkeys []string

					for _, vs := range getkeys {
						sgetkeys = append(sgetkeys, vs.Key)
					}

					dbkeys := strings.Join(sgetkeys, "\n")
					scanner := bufio.NewScanner(strings.NewReader(dbkeys))

					for scanner.Scan() {
						dbkeyscount++
					}

					err = scanner.Err()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t scan count strings of keys error | Path [%s] | %v", vhost, ip, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t scan count strings of keys error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					dbkeyscnt := ""

					if hjson == "1" {
						jcount, _ := json.Marshal(dbkeyscount)
						dbkeyscnt = fmt.Sprintf("{\"count\": %s}", string(jcount))
					} else {
						dbkeyscnt = fmt.Sprintf("%d", dbkeyscount)
					}

					rbytes := []byte(dbkeyscnt)

					conttype := http.DetectContentType(rbytes)
					hsize := fmt.Sprintf("%d", len(rbytes))
					scctrl := fmt.Sprintf("max-age=%d", cctrl)

					ctx.Header("Content-Type", conttype)
					ctx.Header("Content-Length", hsize)
					ctx.Header("Cache-Control", scctrl)

					ctx.Header("Hitcache", "0")

					if search && getcache && expire >= 0 {

						err = cache.Set(vchash, rbytes, expire)
						if err != nil {
							vcerr = "1"
							errmsg = fmt.Sprintf("%v", err)
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Write search results to cache error | Path [%s] | %v", vhost, ip, abs, err)
						}

					}

					ctx.Header("Errcache", vcerr)
					ctx.Header("Errmsg", errmsg)

					_, err = ctx.Write(rbytes)
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

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t find directory error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

		}

		if DirExists(abs) {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Forbidden | Path [%s]", vhost, ip, abs)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Restricted direct access to directory error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

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

		if fromfile == "1" {

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t find file error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if dir == "/" && dbn == "/" {

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t response directly from virtual host root error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if !FileExists(dbf) {

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t find archive db file error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		var keyexists string = ""

		var bf BoltFiles
		var bfiles []BoltFiles

		var dcount int64 = 0

		bf.Name = dbf
		bfiles = append(bfiles, bf)

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
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t lstat db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t lstat db file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if lnfile.Mode()&os.ModeType != 0 {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Non-regular db file error | File [%s] | DB [%s]", vhost, ip, file, dbf)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Non-regular db file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

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

			keyexists, err = KeyExists(db, ibucket, file)
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

			if keyexists != "" {
				db.Close()
				break
			}

			db.Close()

		}

		if keyexists == "" {

			ctx.StatusCode(iris.StatusNotFound)

			if log4xx {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 404 | Not found | Path [%s]", vhost, ip, abs)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t find file in archive db error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		bucket = keyexists

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

		// Header Bolt Reader

		var pheader []byte

		err = db.View(func(tx *bolt.Tx) error {

			verr := errors.New("bucket not exists")

			b := tx.Bucket([]byte(bucket))
			if b != nil {
				pheader = b.GetLimit([]byte(file), uint32(548))
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

		headbuffer := make([]byte, 36)

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
					pdata = b.GetRange([]byte(file), uint32(rstart+36), uint32(rlength))
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
				pdata = b.GetOffset([]byte(file), uint32(36))
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

			rcrc := crc32.Checksum(fullbuffer.Bytes(), ctbl32)

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
