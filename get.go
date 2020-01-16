package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/eltaline/bolt"
	"github.com/kataras/iris"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Get

func ZDGet() iris.Handler {
	return func(ctx iris.Context) {
		defer wg.Done()

		// Wait Group

		wg.Add(1)

		// Loggers

		getLogger, getlogfile := GetLogger()
		defer getlogfile.Close()

		// Vhost / IP Client

		ip := ctx.RemoteAddr()
		vhost := ctx.Host()

		// Shutdown

		if wshutdown {
			ctx.StatusCode(iris.StatusInternalServerError)
			//_, err := ctx.WriteString("Shutdown wZD server in progress\n")
			//if err != nil {
			//	getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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

		opentries := 5
		locktimeout := 5

		args := false
		cctrl := 0

		minbuffer := int64(262144)
		lowbuffer := int64(1048576)
		medbuffer := int64(67108864)
		bigbuffer := int64(536870912)

		filemode := os.FileMode(0640)

		for _, Server := range config.Server {

			if vhost == Server.HOST {

				badhost = false

				base = Server.ROOT

				getbolt = Server.GETBOLT
				getcount = Server.GETCOUNT
				getkeys = Server.GETKEYS

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

				break

			}

		}

		if badhost {

			ctx.StatusCode(iris.StatusMisdirectedRequest)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Not found configured virtual host", vhost, ip)

			if debugmode {

				_, err := ctx.Writef("[ERRO] Not found configured virtual host | Virtual Host [%s]\n", vhost)
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if !args {

			params := ctx.URLParams()

			if len(params) != 0 {

				ctx.StatusCode(iris.StatusForbidden)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The query arguments is not allowed during GET request", vhost, ip)

				if debugmode {

					_, err := ctx.WriteString("[ERRO] The query arguments is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The bolt request is not allowed during GET request", vhost, ip)

				if debugmode {

					_, err := ctx.WriteString("[ERRO] The request is not allowed during GET request\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

		}

		hcount := ctx.GetHeader("KeysCount")

		if !getcount && hcount == "1" {

			ctx.StatusCode(iris.StatusForbidden)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The count request is not allowed during GET request", vhost, ip)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The request is not allowed during GET request\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		hkeys := ctx.GetHeader("Keys")
		hkeysall := ctx.GetHeader("KeysAll")

		if !getkeys && (hkeys == "1" || hkeysall == "1") {

			ctx.StatusCode(iris.StatusForbidden)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | The count request is not allowed during GET request", vhost, ip)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] The request is not allowed during GET request\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}

		if hkeys == "1" && hkeysall == "1" {

			ctx.StatusCode(iris.StatusConflict)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t serve Keys and KeysAll header together due to conflict error", vhost, ip)

			if debugmode {

				_, err := ctx.WriteString("[ERRO] Can`t serve Keys and KeysAll header together due to conflict error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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

		if DirExists(abs) && hcount == "1" {

			if !FileExists(dbk) {

				filecount, err := FileCount(abs)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t count files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count files in directory error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				_, err = ctx.Writef("%d\n", filecount)
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

				return

			}

			if FileExists(dbk) {

				db, err := BoltOpenRead(dbk, filemode, timeout, opentries)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}
				defer db.Close()

				filecount, err := FileCount(abs)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t count files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count files in directory error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				keycount, err := KeyCount(db, bucket)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t count keys of files in db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count keys of files in db bucket error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Writef("%d\n", (keycount + filecount - 1))
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

				db.Close()
				return

			}

			ctx.StatusCode(iris.StatusNotFound)
			return

		}

		// Standart/Bolt Keys Iterator

		if DirExists(abs) && (hkeys == "1" || hkeysall == "1") {

			var keysbuffer bytes.Buffer

			if !FileExists(dbk) {

				getkeys, err := FileKeys(abs)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t iterate files in directory error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate files in directory error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				allkeys := fmt.Sprintf("%s\n", strings.Join(getkeys, "\n"))

				err = binary.Write(&keysbuffer, Endian, []byte(allkeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Write keys names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write keys names to keysbuffer error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

				return

			}

			if FileExists(dbk) {

				uniq := true

				if hkeysall == "1" {
					uniq = false
				}

				db, err := BoltOpenRead(dbk, filemode, timeout, opentries)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}
				defer db.Close()

				getkeys, err := AllKeys(db, bucket, abs, uniq)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t iterate keys of files in db bucket error | DB [%s] | %v", vhost, ip, dbk, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t iterate keys of files in db bucket error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				allkeys := fmt.Sprintf("%s\n", strings.Join(getkeys, "\n"))

				err = binary.Write(&keysbuffer, Endian, []byte(allkeys))
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Write keys names to keysbuffer error | Directory [%s] | %v", vhost, ip, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write keys names to keysbuffer error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Write(keysbuffer.Bytes())
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

				db.Close()
				return

			}

			ctx.StatusCode(iris.StatusNotFound)
			return

		}

		if DirExists(abs) {

			ctx.StatusCode(iris.StatusForbidden)
			return

		}

		// Standart Reader

		if FileExists(abs) && fromarchive != "1" {

			infile, err := os.Stat(abs)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t stat file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t stat file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t open file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}
			defer pfile.Close()

			contbuffer := make([]byte, 512)

			csizebuffer, err := pfile.Read(contbuffer)
			if err != nil && err != io.EOF {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | csizebuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				err = pfile.Close()
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						ctx.StatusCode(iris.StatusInternalServerError)
						_, err = ctx.WriteString("[ERRO] Close during read file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] csizebuffer read file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				return

			}

			conttype, err := ContentType(file, size, contbuffer, csizebuffer)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | contbuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				err = pfile.Close()
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during contbuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Close during contbuffer read file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] contbuffer read file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close after etag/modtime file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
					return
				}

				ctx.StatusCode(iris.StatusNotModified)
				return

			}

			if method == "HEAD" || method == "OPTIONS" {

				err = pfile.Close()
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close after head/options file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
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

				reqr, err := ParseByRange(rngs, size)
				if err != nil {

					ctx.StatusCode(iris.StatusRequestedRangeNotSatisfiable)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Invalid range error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t seek to position [%d] error | File [%s] | Path [%s] | %v", vhost, ip, rstart, file, abs, err)

					err = pfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during seek file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close during seek file error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

					if debugmode {

						_, err = ctx.Writef("[ERRO] Can`t seek to position [%d] error\n", rstart)
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
							//getLogger.Infof("| sizebuffer end of file | File [%s] | Path [%s] | %v", file, abs, err)
							break
						}

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | sizebuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						err = pfile.Close()
						if err != nil {

							ctx.StatusCode(iris.StatusInternalServerError)
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

							if debugmode {

								_, err = ctx.WriteString("[ERRO] Close during read file error\n")
								if err != nil {
									getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
								}

							}

							return

						}

						if debugmode {

							_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

					_, err = ctx.Write(readbuffer[:sizebuffer])
					if err != nil {

						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)

						err = pfile.Close()
						if err != nil {

							ctx.StatusCode(iris.StatusInternalServerError)
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during readbuffer send file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

							if debugmode {

								_, err = ctx.WriteString("[ERRO] Close during readbuffer send file error\n")
								if err != nil {
									getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close after send range of file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
					return
				}

				return

			}

			// Standart File Reader

			_, err = pfile.Seek(0, 0)
			if err != nil {

				ctx.StatusCode(iris.StatusRequestedRangeNotSatisfiable)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t seek to position 0 error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

				err = pfile.Close()
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during seek file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Close during seek file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t seek to position 0 error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
						//getLogger.Infof("| sizebuffer end of file | File [%s] | Path [%s] | %v", file, abs, err)
						break
					}

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | sizebuffer read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					err = pfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during read file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close during read file error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
							}

						}

						return

					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					return

				}

				_, err = ctx.Write(readbuffer[:sizebuffer])
				if err != nil {

					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)

					err = pfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close during readbuffer send file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close during readbuffer send file error\n")
							if err != nil {
								getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Close after send file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)
				return
			}

			return

		}

		// Bolt Reader

		if dir == "/" && dbn == "/" {
			ctx.StatusCode(iris.StatusNotFound)
			return
		}

		if !FileExists(dbf) {
			ctx.StatusCode(iris.StatusNotFound)
			return
		}

		db, err := BoltOpenRead(dbf, filemode, timeout, opentries)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			return

		}
		defer db.Close()

		keyexists, err := KeyExists(db, bucket, file)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t check key of file in db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t check key of file in db bucket error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t get data header by key from db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t get data header by key from db error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Read header data from db error | File [%s] | DB [%s] | Header Buffer [%p] | %v", vhost, ip, file, dbf, headbuffer, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Read header data from db error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			return

		}

		hread := bytes.NewReader(headbuffer[:hsizebuffer])

		err = binary.Read(hread, Endian, &readhead)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Read binary header data from db error | File [%s] | DB [%s] | Header Buffer [%p] | %v", vhost, ip, file, dbf, hread, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Read binary header data from db error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | csizebuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] csizebuffer read file error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
				}

			}

			db.Close()
			return

		}

		conttype, err := ContentType(file, size, contbuffer, csizebuffer)
		if err != nil {

			ctx.StatusCode(iris.StatusInternalServerError)
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | contbuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] contbuffer read file error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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

			reqr, err := ParseByRange(rngs, size)
			if err != nil {

				ctx.StatusCode(iris.StatusRequestedRangeNotSatisfiable)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Invalid range error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t get data by key from db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t get data by key from db error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
						//getLogger.Infof("| sizebuffer end of file | File [%s] | DB [%s] | %v", file, dbf, err)
						break
					}

					ctx.StatusCode(iris.StatusInternalServerError)
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | sizebuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
						if err != nil {
							getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
						}

					}

					db.Close()
					return

				}

				_, err = ctx.Write(readbuffer[:sizebuffer])
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
			getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t get data by key from db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Can`t get data by key from db error\n")
				if err != nil {
					getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t read data to fullbuffer error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t read data to fullbuffer error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				db.Close()
				return

			}

			tbl := crc32.MakeTable(0xEDB88320)
			rcrc := crc32.Checksum(fullbuffer.Bytes(), tbl)

			if rcrc != crc {

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | CRC read file error | File [%s] | DB [%s] | Have CRC [%v] | Awaiting CRC [%v]", vhost, ip, file, dbf, rcrc, crc)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] CRC read file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				db.Close()
				return

			}

			_, err = ctx.Write(fullbuffer.Bytes())
			if err != nil {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
					//getLogger.Infof("| sizebuffer end of file | File [%s] | DB [%s] | %v", file, dbf, err)
					break
				}

				ctx.StatusCode(iris.StatusInternalServerError)
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | sizebuffer read file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] sizebuffer read file error\n")
					if err != nil {
						getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
					}

				}

				db.Close()
				return

			}

			_, err = ctx.Write(readbuffer[:sizebuffer])
			if err != nil {
				getLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | Can`t complete response to client", vhost, ip)
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
