package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coocood/freecache"
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
func ZDGet(cache *freecache.Cache) iris.Handler {
	return func(ctx iris.Context) {
		defer wg.Done()

		var err error

		// Wait Group

		wg.Add(1)

		// Loggers

		getLogger, getlogfile := GetLogger()
		defer getlogfile.Close()

		// Shutdown

		if wshutdown {
			ctx.StatusCode(iris.StatusInternalServerError)
			// _, err = ctx.WriteString("[ERRO] Shutdown wZD server in progress\n")
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
		getvalue := false
		getcount := false
		getcache := false

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

		bft := int64(36)

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
				getsearch = Server.GETSEARCH
				getrecursive = Server.GETRECURSIVE
				getvalue = Server.GETVALUE
				getcount = Server.GETCOUNT
				getcache = Server.GETCACHE

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

		if method == "GET" && hsea == "1" {

			expression := ""
			recursive := uint8(0)
			stopfirst := uint8(0)
			withurl := false
			withvalue := false

			minsize := uint64(0)
			maxsize := uint64(0)

			minstmp := uint64(0)
			maxstmp := uint64(0)

			limit := uint64(0)
			offset := uint64(0)

			expire := int(-1)
			skipcache := false

			sbucket := "size"
			tbucket := "time"

			hkeys := ctx.GetHeader("Keys")
			hkeysall := ctx.GetHeader("KeysAll")
			hkeysfiles := ctx.GetHeader("KeysFiles")
			hkeysarchives := ctx.GetHeader("KeysArchives")

			hinfo := ctx.GetHeader("KeysInfo")
			hinfoall := ctx.GetHeader("KeysInfoAll")
			hinfofiles := ctx.GetHeader("KeysInfoFiles")
			hinfoarchives := ctx.GetHeader("KeysInfoArchives")

			hsearch := ctx.GetHeader("KeysSearch")
			hsearchall := ctx.GetHeader("KeysSearchAll")
			hsearchfiles := ctx.GetHeader("KeysSearchFiles")
			hsearcharchives := ctx.GetHeader("KeysSearchArchives")

			hcount := ctx.GetHeader("KeysCount")
			hcountall := ctx.GetHeader("KeysCountAll")
			hcountfiles := ctx.GetHeader("KeysCountFiles")
			hcountarchives := ctx.GetHeader("KeysCountArchives")

			hexpression := ctx.GetHeader("Expression")
			hrecursive := ctx.GetHeader("Recursive")
			hstopfirst := ctx.GetHeader("StopFirst")

			hminsize := ctx.GetHeader("MinSize")
			hmaxsize := ctx.GetHeader("MaxSize")

			hminstmp := ctx.GetHeader("MinStmp")
			hmaxstmp := ctx.GetHeader("MaxStmp")

			hwithurl := ctx.GetHeader("WithUrl")
			hwithvalue := ctx.GetHeader("WithValue")

			hlimit := ctx.GetHeader("Limit")
			hoffset := ctx.GetHeader("Offset")

			hexpire := ctx.GetHeader("Expire")
			hskipcache := ctx.GetHeader("SkipCache")

			hjson := ctx.GetHeader("JSON")

			if !getkeys && (hkeys != "" || hkeysall != "" || hkeysfiles != "" || hkeysarchives != "") {

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

			if !getinfo && (hinfo != "" || hinfoall != "" || hinfofiles != "" || hinfoarchives != "") {

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

			if !getsearch && (hsearch != "" || hsearchall != "" || hsearchfiles != "" || hsearcharchives != "" || hexpression != "") {

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

			if !getcount && (hcount != "" || hcountall != "" || hcountfiles != "" || hcountarchives != "") {

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

			if hexpression != "" {
				expression = hexpression
			} else {
				expression = "(.+)"
			}

			if hrecursive != "" {

				recursive64, err := strconv.ParseUint(hrecursive, 10, 8)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Recursive uint error during GET keys* request | Recursive [%s] | %v", vhost, ip, hrecursive, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Recursive uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				if recursive64 > 3 {
					recursive = 3
				} else {
					recursive = uint8(recursive64)
				}

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

			if hlimit != "" {

				limit, err = strconv.ParseUint(hlimit, 10, 64)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Limit uint error during GET keys* request | Limit [%s] | %v", vhost, ip, hlimit, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Limit uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

			}

			if hoffset != "" {

				offset, err = strconv.ParseUint(hoffset, 10, 64)
				if err != nil {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Offset uint error during GET keys* request | Offset [%s] | %v", vhost, ip, hoffset, err)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Offset uint error during GET keys* request\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

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

			var vckey []byte = nil
			var vcerr string = "0"
			var errmsg string = "none"

			if getcache && !skipcache {

				vckey = []byte("host:" + vhost + ";path:" + abs + ";params:" + fmt.Sprintf("%s", params) + ";hk:" + hkeys + ";hkl:" + hkeysall + ";hkf:" + hkeysfiles + ";hka:" + hkeysarchives +
					";hi:" + hinfo + ";hil:" + hinfoall + ";hif:" + hinfofiles + ";hia:" + hinfoarchives +
					";hs:" + hsearch + ";hsl:" + hsearchall + ";hsf:" + hsearchfiles + ";hsa:" + hsearcharchives +
					";hc:" + hcount + ";hcl:" + hcountall + ";hcf:" + hcountfiles + ";hca:" + hcountarchives +
					";he:" + hexpression + ";hr:" + hrecursive + ";ht:" + hstopfirst +
					";hmix:" + hminsize + ";hmax:" + hmaxsize + ";hsix:" + hminstmp + ";hsax:" + hmaxstmp +
					";hwrl:" + hwithurl + ";hwvl:" + hwithvalue + ";hlim:" + hlimit + ";hoff:" + hoffset + ";hjsn:" + hjson)

				vcget, err := cache.Get(vckey)
				if err == nil {

					conttype := http.DetectContentType(vcget)

					hsize := fmt.Sprintf("%d", (len(vcget)))
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

			// Standart/Bolt Keys Iterator

			istrue, ccnm := StringOne(hkeys, hkeysall, hkeysfiles, hkeysarchives)

			switch {

			case istrue && (ccnm == 1 || ccnm == 2):

				uniq := true

				if ccnm == 2 {
					uniq = false
				}

				if DirExists(abs) {

					getkeys, err := AllKeys(ibucket, sbucket, tbucket, filemode, timeout, opentries, freelist, abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, uniq)
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
							allkeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, "\n")
							}

							allkeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

						}

						rbytes := []byte(allkeys)

						conttype := http.DetectContentType(rbytes)

						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if getcache && expire >= 0 {

							err = cache.Set(vckey, rbytes, expire)
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

					getkeys, err := FileKeys(abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi)
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
							filekeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, "\n")
							}

							filekeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

						}

						rbytes := []byte(filekeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if getcache && expire >= 0 {

							err = cache.Set(vckey, rbytes, expire)
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

			case istrue && ccnm == 4:

				if DirExists(abs) {

					getkeys, err := DBKeys(ibucket, sbucket, tbucket, filemode, timeout, opentries, freelist, abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi)
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
							dbkeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, "\n")
							}

							dbkeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

						}

						rbytes := []byte(dbkeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if getcache && expire >= 0 {

							err = cache.Set(vckey, rbytes, expire)
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

			istrue, ccnm = StringOne(hinfo, hinfoall, hinfofiles, hinfoarchives)

			switch {

			case istrue && (ccnm == 1 || ccnm == 2):

				uniq := true

				if ccnm == 2 {
					uniq = false
				}

				if DirExists(abs) {

					getkeys, err := AllKeysInfo(ibucket, sbucket, tbucket, filemode, timeout, opentries, freelist, abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, uniq)
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
							allkeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							allkeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

						}

						rbytes := []byte(allkeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if getcache && expire >= 0 {

							err = cache.Set(vckey, rbytes, expire)
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

					getkeys, err := FileKeysInfo(abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi)
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
							filekeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							filekeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

						}

						rbytes := []byte(filekeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if getcache && expire >= 0 {

							err = cache.Set(vckey, rbytes, expire)
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

			case istrue && ccnm == 4:

				if DirExists(abs) {

					getkeys, err := DBKeysInfo(ibucket, sbucket, tbucket, filemode, timeout, opentries, freelist, abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi)
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
							dbkeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							dbkeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

						}

						rbytes := []byte(dbkeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if getcache && expire >= 0 {

							err = cache.Set(vckey, rbytes, expire)
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

			istrue, ccnm = StringOne(hsearch, hsearchall, hsearchfiles, hsearcharchives)

			switch {

			case istrue && (ccnm == 1 || ccnm == 2):

				uniq := true

				if ccnm == 2 {
					uniq = false
				}

				if DirExists(abs) {

					getkeys, err := AllKeysSearch(ibucket, sbucket, tbucket, filemode, timeout, opentries, freelist, abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withvalue, vmaxsize, uniq)
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
							allkeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							allkeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

						}

						rbytes := []byte(allkeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if getcache && expire >= 0 {

							err = cache.Set(vckey, rbytes, expire)
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

					getkeys, err := FileKeysSearch(abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withvalue, vmaxsize)
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
							filekeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							filekeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

						}

						rbytes := []byte(filekeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if getcache && expire >= 0 {

							err = cache.Set(vckey, rbytes, expire)
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

			case istrue && ccnm == 4:

				if DirExists(abs) {

					getkeys, err := DBKeysSearch(ibucket, sbucket, tbucket, filemode, timeout, opentries, freelist, abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, withvalue, vmaxsize)
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
							dbkeys = fmt.Sprintf("{\n\t\"keys\": %s\n}\n", string(jkeys))
						} else {

							var sgetkeys []string

							for _, vs := range getkeys {
								sgetkeys = append(sgetkeys, vs.Key, strconv.FormatUint(vs.Size, 10), strconv.FormatUint(vs.Date, 10), strconv.FormatInt(int64(vs.Type), 10), "\n")
							}

							dbkeys = strings.Join(strings.SplitAfterN(strings.Replace(strings.Trim(fmt.Sprintf("%s", sgetkeys), "[]"), "\n ", "\n", -1), "\n", 1), "\n")

						}

						rbytes := []byte(dbkeys)

						conttype := http.DetectContentType(rbytes)
						hsize := fmt.Sprintf("%d", len(rbytes))
						scctrl := fmt.Sprintf("max-age=%d", cctrl)

						ctx.Header("Content-Type", conttype)
						ctx.Header("Content-Length", hsize)
						ctx.Header("Cache-Control", scctrl)

						ctx.Header("Hitcache", "0")

						if getcache && expire >= 0 {

							err = cache.Set(vckey, rbytes, expire)
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

			istrue, ccnm = StringOne(hcount, hcountall, hcountfiles, hcountarchives)

			switch {

			case istrue && (ccnm == 1 || ccnm == 2):

				uniq := true

				if ccnm == 2 {
					uniq = false
				}

				limit = 0
				offset = 0

				if DirExists(abs) {

					allkeyscount := 0

					getkeys, err := AllKeys(ibucket, sbucket, tbucket, filemode, timeout, opentries, freelist, abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi, uniq)
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
						allkeyscnt = fmt.Sprintf("{\n\t\"count\": %s\n}\n", string(jcount))
					} else {
						allkeyscnt = fmt.Sprintf("%d\n", allkeyscount)
					}

					rbytes := []byte(allkeyscnt)

					conttype := http.DetectContentType(rbytes)
					hsize := fmt.Sprintf("%d", len(rbytes))
					scctrl := fmt.Sprintf("max-age=%d", cctrl)

					ctx.Header("Content-Type", conttype)
					ctx.Header("Content-Length", hsize)
					ctx.Header("Cache-Control", scctrl)

					ctx.Header("Hitcache", "0")

					if getcache && expire >= 0 {

						err = cache.Set(vckey, rbytes, expire)
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

				filekeyscount := 0

				limit = 0
				offset = 0

				if DirExists(abs) {

					getkeys, err := FileKeys(abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi)
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
						filekeyscnt = fmt.Sprintf("{\n\t\"count\": %s\n}\n", string(jcount))
					} else {
						filekeyscnt = fmt.Sprintf("%d\n", filekeyscount)
					}

					rbytes := []byte(filekeyscnt)

					conttype := http.DetectContentType(rbytes)
					hsize := fmt.Sprintf("%d", len(rbytes))
					scctrl := fmt.Sprintf("max-age=%d", cctrl)

					ctx.Header("Content-Type", conttype)
					ctx.Header("Content-Length", hsize)
					ctx.Header("Cache-Control", scctrl)

					ctx.Header("Hitcache", "0")

					if getcache && expire >= 0 {

						err = cache.Set(vckey, rbytes, expire)
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

			case istrue && ccnm == 4:

				dbkeyscount := 0

				limit = 0
				offset = 0

				if DirExists(abs) {

					getkeys, err := DBKeys(ibucket, sbucket, tbucket, filemode, timeout, opentries, freelist, abs, limit, offset, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, furi)
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
						dbkeyscnt = fmt.Sprintf("{\n\t\"count\": %s\n}\n", string(jcount))
					} else {
						dbkeyscnt = fmt.Sprintf("%d\n", dbkeyscount)
					}

					rbytes := []byte(dbkeyscnt)

					conttype := http.DetectContentType(rbytes)
					hsize := fmt.Sprintf("%d", len(rbytes))
					scctrl := fmt.Sprintf("max-age=%d", cctrl)

					ctx.Header("Content-Type", conttype)
					ctx.Header("Content-Length", hsize)
					ctx.Header("Cache-Control", scctrl)

					ctx.Header("Hitcache", "0")

					if getcache && expire >= 0 {

						err = cache.Set(vckey, rbytes, expire)
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

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t find file in archive db error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

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

		if tmst > 4294967295 {
			bft = int64(32)
		}

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
					pdata = b.GetRange([]byte(file), uint32(rstart+bft), uint32(rlength))
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
				pdata = b.GetOffset([]byte(file), uint32(bft))
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
