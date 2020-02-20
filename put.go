package main

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/eltaline/bolt"
	"github.com/eltaline/mmutex"
	"github.com/eltaline/nutsdb"
	"github.com/kataras/iris"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Put

// ZDPut : PUT/POST/PATCH methods
func ZDPut(keymutex *mmutex.Mutex, cdb *nutsdb.DB, ndb *nutsdb.DB, wg *sync.WaitGroup) iris.Handler {
	return func(ctx iris.Context) {
		defer wg.Done()

		var err error

		// Wait Group

		wg.Add(1)

		// Loggers

		putLogger, putlogfile := PutLogger()
		defer putlogfile.Close()

		// Vhost / IP Client

		ip := ctx.RemoteAddr()
		cip := net.ParseIP(ip)
		vhost := strings.Split(ctx.Host(), ":")[0]

		// Shutdown

		if shutdown {
			ctx.StatusCode(iris.StatusInternalServerError)
			// _, err = ctx.WriteString("[ERRO] Shutdown wZD server in progress\n")
			// if err != nil {
			//      putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client| %v", vhost, ip, err)
			// }
			return
		}

		uri := ctx.Path()
		params := ctx.URLParams()
		archive := ctx.GetHeader("Archive")
		tofile := ctx.GetHeader("File")
		length := ctx.GetHeader("Content-Length")
		ctype := ctx.GetHeader("Content-Type")

		hcompact := ctx.GetHeader("Compact")

		badhost := true
		badip := true

		base := "/notfound"

		upload := false

		compaction := true
		compact := false

		nonunique := false

		writeintegrity := true

		trytimes := 5
		opentries := 5
		locktimeout := 5

		skeyscnt := 262144
		smaxsize := int64(536870912)

		fmaxsize := int64(1048576)

		minbuffer := int64(262144)
		lowbuffer := int64(1048576)
		medbuffer := int64(67108864)
		bigbuffer := int64(536870912)

		filemode := os.FileMode(0640)
		dirmode := os.FileMode(0750)

		deldir := false

		log4xx := true

		var vfilemode int64 = 640

		dir := filepath.Dir(uri)
		file := filepath.Base(uri)

		for _, Server := range config.Server {

			if vhost == Server.HOST {

				badhost = false

				base = filepath.Clean(Server.ROOT)

				for _, Vhost := range putallow {

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

				upload = Server.UPLOAD

				compaction = Server.COMPACTION

				nonunique = Server.NONUNIQUE

				writeintegrity = Server.WRITEINTEGRITY

				trytimes = Server.TRYTIMES
				opentries = Server.OPENTRIES
				locktimeout = Server.LOCKTIMEOUT

				skeyscnt = Server.SKEYSCNT

				smaxsize = Server.SMAXSIZE
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

				log4xx = Server.LOG4XX

				break

			}

		}

		if badhost {

			ctx.StatusCode(iris.StatusMisdirectedRequest)

			if log4xx {
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 421 | Not found configured virtual host", vhost, ip)
			}

			if debugmode {

				_, err = ctx.Writef("[ERRO] Not found configured virtual host | Virtual Host [%s]\n", vhost)
				if err != nil {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if badip {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Forbidden", vhost, ip)
			}

			if debugmode {

				_, err = ctx.Writef("[ERRO] Not found allowed ip | Virtual Host [%s]\n", vhost)
				if err != nil {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if !upload {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Upload disabled", vhost, ip)
			}

			if debugmode {

				_, err = ctx.Writef("[ERRO] Upload disabled | Virtual Host [%s]\n", vhost)
				if err != nil {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if len(params) != 0 {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | The query arguments is not allowed during PUT request", vhost, ip)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] The query arguments is not allowed during PUT request\n")
				if err != nil {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		mchctype := rgxctype.MatchString(ctype)

		if mchctype {

			ctx.StatusCode(iris.StatusBadRequest)

			if log4xx {
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | The multipart query is not allowed during PUT request", vhost, ip)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] The multipart query is not allowed during PUT request\n")
				if err != nil {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		clength, err := strconv.ParseInt(length, 10, 64)
		if err != nil {

			ctx.StatusCode(iris.StatusBadRequest)

			if log4xx {
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Content length error during PUT request | Content-Length [%s] | %v", vhost, ip, length, err)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Content length error during PUT request\n")
				if err != nil {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if clength == 0 {

			ctx.StatusCode(iris.StatusBadRequest)

			if log4xx {
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | The body was empty during PUT request | Content-Length [%s]", vhost, ip, length)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] The body was empty during PUT request\n")
				if err != nil {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if hcompact != "" {

			compact64, err := strconv.ParseUint(hcompact, 10, 8)
			if err != nil {

				ctx.StatusCode(iris.StatusBadRequest)

				if log4xx {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | Compact uint error during PUT request | Compact [%s] | %v", vhost, ip, hcompact, err)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Compact uint error during PUT request\n")
					if err != nil {
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			if compact64 >= 1 {
				compact = true
			}

		}

		now := time.Now()
		sec := now.Unix()

		tb := make([]byte, 8)
		Endian.PutUint64(tb, uint64(sec))

		abs := filepath.Clean(base + dir + "/" + file)
		ddir := filepath.Clean(base + dir)

		dbn := filepath.Base(dir)
		dbf := filepath.Clean(base + dir + "/" + dbn + ".bolt")

		bucket := "wzd1"
		ibucket := "index"
		sbucket := "size"
		tbucket := "time"
		cbucket := "count"

		timeout := time.Duration(locktimeout) * time.Second

		mchregbolt := rgxbolt.MatchString(file)
		mchregcrcbolt := rgxcrcbolt.MatchString(file)

		if file == "/" {

			ctx.StatusCode(iris.StatusBadRequest)

			if log4xx {
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | No given file name error | File [%s]", vhost, ip, file)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] No given file name error\n")
				if err != nil {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

			return

		}

		if mchregbolt || mchregcrcbolt {

			ctx.StatusCode(iris.StatusForbidden)

			if log4xx {
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Restricted to upload .bolt or .crcbolt as bolt-in-bolt archive error | File [%s]", vhost, ip, file)
			}

			if debugmode {

				_, err = ctx.WriteString("[ERRO] Restricted to upload .bolt or .crcbolt as bolt-in-bolt archive error\n")
				if err != nil {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
				}

			}

		}

		if !DirExists(ddir) {
			err = os.MkdirAll(ddir, dirmode)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t create directory error | Directory [%s] | %v", vhost, ip, ddir, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t create directory error\n")
					if err != nil {
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			err = os.Chmod(ddir, dirmode)
			if err != nil {

				ctx.StatusCode(iris.StatusInternalServerError)
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t chmod directory error | Directory [%s] | %v", vhost, ip, ddir, err)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t chmod directory error\n")
					if err != nil {
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

		}

		// Standart Writer

		if archive != "1" || tofile == "1" || clength > fmaxsize {

			if FileExists(dbf) && !nonunique {

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
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t lstat db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t lstat db file error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					if lnfile.Mode()&os.ModeType != 0 {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Non-regular db file error | File [%s] | DB [%s]", vhost, ip, file, dbf)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Non-regular db file error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					db, err := BoltOpenRead(dbf, filemode, timeout, opentries, freelist)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t open db file error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						return

					}

					keyexists, err := KeyExists(db, ibucket, file)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t check key of file in index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t check key of file in index db bucket error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						return

					}

					if keyexists != "" {

						ctx.StatusCode(iris.StatusConflict)

						if log4xx {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 409 | Can`t upload standart file due to conflict with duplicate key/file name in index db bucket error | File [%s] | DB [%s]", vhost, ip, file, dbf)
						}

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t upload standart file due to conflict with duplicate key/file name in index db bucket error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						return

					}

					db.Close()

				}

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
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open/create file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open/create file error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					keymutex.Unlock(abs)
					return

				}
				defer wfile.Close()

				err = os.Chmod(abs, filemode)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t chmod file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t chmod file error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
									// putLogger.Infof("| sizebuffer end of file | File [%s] | Path [%s] | %v", file, abs, err)
									break
								}

								_, err = wfile.Write(endbuffer[:sizebuffer])
								if err != nil {

									ctx.StatusCode(iris.StatusInternalServerError)
									putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write sizebuffer during write to file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

									err = wfile.Close()
									if err != nil {

										ctx.StatusCode(iris.StatusInternalServerError)
										putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close during write file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

										if debugmode {

											_, err = ctx.WriteString("[ERRO] Close during write file error\n")
											if err != nil {
												putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
											}

										}

										keymutex.Unlock(abs)
										return

									}

									if debugmode {

										_, err = ctx.WriteString("[ERRO] Write sizebuffer during write to file error\n")
										if err != nil {
											putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
										}

									}

									keymutex.Unlock(abs)
									return

								}

								break

							}

							ctx.StatusCode(iris.StatusInternalServerError)
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | sizebuffer write file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

							if debugmode {

								_, err = ctx.WriteString("[ERRO] sizebuffer write file error\n")
								if err != nil {
									putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
								}

							}

							break

						}

						_, err = wfile.Write(endbuffer[:sizebuffer])
						if err != nil {

							ctx.StatusCode(iris.StatusInternalServerError)
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write sizebuffer last write to file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

							err = wfile.Close()
							if err != nil {

								ctx.StatusCode(iris.StatusInternalServerError)
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close last write file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

								if debugmode {

									_, err = ctx.WriteString("[ERRO] Close last write file error\n")
									if err != nil {
										putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
									}

								}

								keymutex.Unlock(abs)
								return

							}

							if debugmode {

								_, err = ctx.WriteString("[ERRO] Write sizebuffer last write to file error\n")
								if err != nil {
									putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t stat uploaded file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t stat uploaded file error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						keymutex.Unlock(abs)
						return

					}

					realsize := upfile.Size()

					if realsize != clength {

						ctx.StatusCode(iris.StatusBadRequest)

						if log4xx {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | The body length != real length during PUT request | Content-Length [%s] | Real Size [%d]", vhost, ip, length, realsize)
						}

						if debugmode {

							_, err = ctx.WriteString("[ERRO] The body length != real length during PUT request\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						if FileExists(abs) {
							err = RemoveFile(abs, ddir, deldir)
							if err != nil {

								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 599 | Can`t remove bad uploaded file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

								if debugmode {

									_, err = ctx.WriteString("[ERRO] Can`t remove bad uploaded file error\n")
									if err != nil {
										putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
									}

								}

								keymutex.Unlock(abs)
								return

							}

						}

						keymutex.Unlock(abs)
						return

					}

					if search {

						var nval RawKeysData

						dcrc := crc64.Checksum([]byte(ddir), ctbl64)

						radix.Lock()
						tree, _, _ = tree.Insert([]byte(ddir), dcrc)
						radix.Unlock()

						nbucket := strconv.FormatUint(dcrc, 16)

						nkey := []byte("f:" + file)

						nval.Size = uint64(realsize)
						nval.Date = uint64(sec)
						nval.Prnt = uint32(0)
						nval.Buck = uint16(0)
						nval.Type = uint16(0)

						nbuffer := new(bytes.Buffer)

						_ = binary.Write(nbuffer, Endian, nval)

						err = NDBInsert(ndb, nbucket, nkey, nbuffer.Bytes(), 0)
						if err != nil {

							ctx.StatusCode(iris.StatusInternalServerError)
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write file metadata to search db error | File [%s] | Path [%s] | NDB Bucket [%s] | %v", vhost, ip, file, dir, nbucket, err)

							if debugmode {

								_, err = ctx.WriteString("[ERRO] Write file metadata to search db error\n")
								if err != nil {
									putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
								}

							}

							keymutex.Unlock(abs)
							return

						}

					}

					keymutex.Unlock(abs)
					return

				}

				uendbuffer := new(bytes.Buffer)

				_, err = uendbuffer.ReadFrom(ctx.Request().Body)
				if err != nil && err != io.EOF {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t read request body data error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t read request body data error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				realsize := int64(len(uendbuffer.Bytes()))

				if realsize == 0 {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | The body was empty during PUT request | Content-Length [%s]", vhost, ip, length)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] The body was empty during PUT request\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				if realsize != clength {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | The body length != real length during PUT request | Content-Length [%s] | Real Size [%d]", vhost, ip, length, realsize)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] The body length != real length during PUT request\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				_, err = wfile.Write(uendbuffer.Bytes())
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write full buffer write to file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

					err = wfile.Close()
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Close full write file error | File [%s] | Path [%s] | %v", vhost, ip, file, abs, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Close full write file error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						keymutex.Unlock(abs)
						return

					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Write full buffer to file error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					keymutex.Unlock(abs)
					return

				}

				if search {

					var nval RawKeysData

					dcrc := crc64.Checksum([]byte(ddir), ctbl64)

					radix.Lock()
					tree, _, _ = tree.Insert([]byte(ddir), dcrc)
					radix.Unlock()

					nbucket := strconv.FormatUint(dcrc, 16)

					nkey := []byte("f:" + file)

					nval.Size = uint64(realsize)
					nval.Date = uint64(sec)
					nval.Prnt = uint32(0)
					nval.Buck = uint16(0)
					nval.Type = uint16(0)

					nbuffer := new(bytes.Buffer)

					_ = binary.Write(nbuffer, Endian, nval)

					err = NDBInsert(ndb, nbucket, nkey, nbuffer.Bytes(), 0)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write file metadata to search db error | File [%s] | Path [%s] | NDB Bucket [%s] | %v", vhost, ip, file, dir, nbucket, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Write file metadata to search db error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						keymutex.Unlock(abs)
						return

					}

				}

				keymutex.Unlock(abs)
				return

			} else {

				ctx.StatusCode(iris.StatusServiceUnavailable)
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 503 | Timeout mmutex lock error | File [%s] | Path [%s]", vhost, ip, file, abs)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Timeout mmutex lock error\n")
					if err != nil {
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

		}

		// Bolt Writer

		if archive == "1" || clength <= fmaxsize {

			if dbn == "/" {
				ctx.StatusCode(iris.StatusForbidden)

				if log4xx {
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 403 | Can`t upload file to virtual host root error | File [%s]", vhost, ip, file)
				}

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Can`t upload file to virtual host root error\n")
					if err != nil {
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

			var perbucket int = 1024

			switch {
			case clength >= 262144 && clength < 1048576:
				perbucket = 512
			case clength >= 1048576 && clength < 4194304:
				perbucket = 256
			case clength >= 4194304 && clength < 8388608:
				perbucket = 128
			case clength >= 8388608 && clength < 16777216:
				perbucket = 64
			case clength >= 16777216:
				perbucket = 32
			}

			var bf BoltFiles
			var bfiles []BoltFiles

			var bcount int64 = 0
			var ncount int64 = 0
			var dcount int64 = 0

			if FileExists(dbf) {

				bf.Name = dbf
				bfiles = append(bfiles, bf)

				bcount++

			}

			for {

				dcount++
				ndbf := fmt.Sprintf("%s/%s_%08d.bolt", ddir, dbn, dcount)

				if FileExists(ndbf) {

					bcount++

					bf.Name = ndbf
					bfiles = append(bfiles, bf)

				} else {
					break
				}

			}

			if bcount == 0 {

				db, err := BoltOpenWrite(dbf, filemode, timeout, opentries, freelist)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open/create db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open/create db file error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}
				defer db.Close()

				err = os.Chmod(dbf, filemode)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t chmod db error | DB [%s] | %v", vhost, ip, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t chmod db error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				// Keys Index Bucket

				err = db.Update(func(tx *bolt.Tx) error {
					_, err = tx.CreateBucketIfNotExists([]byte(ibucket))
					if err != nil {
						return err
					}
					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t create index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t create index db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				db.Close()

				bf.Name = dbf
				bfiles = append(bfiles, bf)

				bcount++

			}

			for _, bfile := range bfiles {

				ncount++

				dbf = bfile.Name

				lnfile, err := os.Lstat(dbf)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t lstat db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t lstat db file error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				if lnfile.Mode()&os.ModeType != 0 {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Non-regular db file error | File [%s] | DB [%s]", vhost, ip, file, dbf)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Non-regular db file error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				infile, err := os.Stat(dbf)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t stat db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t stat db file error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				bsize := infile.Size()

				db, err := BoltOpenRead(dbf, filemode, timeout, opentries, freelist)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open/create db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open/create db file error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					return

				}

				keyexists, err := KeyExists(db, ibucket, file)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t check key of file in index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t check key of file in index db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					return

				}

				if keyexists != "" {

					db.Close()
					break

				}

				if ncount == bcount {

					keyscnt, err := KeysCount(db, ibucket)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count keys of all files in index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t count keys of all files in index db bucket error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						return

					}

					if bsize >= smaxsize || keyscnt >= skeyscnt {

						db.Close()
						dbf = fmt.Sprintf("%s/%s_%08d.bolt", ddir, dbn, ncount)
						bucket = "wzd1"
						break

					}

				}

				db.Close()

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
				rcrc := uint32(0)

				db, err := BoltOpenWrite(dbf, filemode, timeout, opentries, freelist)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t open/create db file error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t open/create db file error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					keymutex.Unlock(dbf)
					return

				}
				defer db.Close()

				err = os.Chmod(dbf, filemode)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t chmod db error | DB [%s] | %v", vhost, ip, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t chmod db error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				// Keys Index Bucket

				err = db.Update(func(tx *bolt.Tx) error {
					_, err = tx.CreateBucketIfNotExists([]byte(ibucket))
					if err != nil {
						return err
					}
					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t create index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t create index db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				// Keys Size Bucket

				err = db.Update(func(tx *bolt.Tx) error {
					_, err = tx.CreateBucketIfNotExists([]byte(sbucket))
					if err != nil {
						return err
					}
					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t create size db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t create size db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				// Keys Time Bucket

				err = db.Update(func(tx *bolt.Tx) error {
					_, err = tx.CreateBucketIfNotExists([]byte(tbucket))
					if err != nil {
						return err
					}
					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t create time db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t create time db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				// Buckets Internal Sharding Bucket

				err = db.Update(func(tx *bolt.Tx) error {
					_, err = tx.CreateBucketIfNotExists([]byte(cbucket))
					if err != nil {
						return err
					}
					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t create count db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t create count db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				keyexists, err := KeyExists(db, ibucket, file)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t check key of file in index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t check key of file in index db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				keybucket, err := BucketCount(db, cbucket)
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count buckets in count db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t count buckets in count db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if keybucket > uint64(0) && keyexists == "" {

					lastbucket := fmt.Sprintf("wzd%d", keybucket)

					keyscount, err := KeysCountBucket(db, lastbucket)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count keys of files in last db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t count keys of files in last db bucket error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					keybytes, err := BucketStats(db, lastbucket)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t count bytes of files in last db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t count bytes of files in last db bucket error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					if keyscount >= perbucket || keybytes >= 536870912 {

						bucket = fmt.Sprintf("wzd%d", keybucket+1)

						nb := make([]byte, 8)
						Endian.PutUint64(nb, keybucket+1)

						err = db.Update(func(tx *bolt.Tx) error {

							verr := errors.New("count bucket not exists")

							b := tx.Bucket([]byte(cbucket))
							if b != nil {
								err = b.Put([]byte("counter"), nb)
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
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t write bucket counter to count db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

							if debugmode {

								_, err = ctx.WriteString("[ERRO] Can`t write bucket counter to count db bucket error\n")
								if err != nil {
									putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
								}

							}

							db.Close()
							keymutex.Unlock(dbf)
							return

						}

					} else {
						bucket = lastbucket
					}

				} else if keyexists != "" {

					bucket = keyexists

				} else {

					nb := make([]byte, 8)
					Endian.PutUint64(nb, uint64(1))

					err = db.Update(func(tx *bolt.Tx) error {

						verr := errors.New("count bucket not exists")

						b := tx.Bucket([]byte(cbucket))
						if b != nil {
							err = b.Put([]byte("counter"), nb)
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
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t write bucket counter to count db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t write bucket counter to count db bucket error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				}

				err = db.Update(func(tx *bolt.Tx) error {
					_, err = tx.CreateBucketIfNotExists([]byte(bucket))
					if err != nil {
						return err
					}
					return nil

				})
				if err != nil {

					ctx.StatusCode(iris.StatusInternalServerError)
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t create db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t create db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t read request body data error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t read request body data error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				realsize := int64(len(rawbuffer.Bytes()))

				if realsize == 0 {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | The body was empty during PUT request | Content-Length [%s]", vhost, ip, length)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] The body was empty during PUT request\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if realsize != clength {

					ctx.StatusCode(iris.StatusBadRequest)

					if log4xx {
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 400 | The body length != real length during PUT request | Content-Length [%s] | Real Size [%d]", vhost, ip, length, realsize)
					}

					if debugmode {

						_, err = ctx.WriteString("[ERRO] The body length != real length during PUT request\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				sb := make([]byte, 8)
				Endian.PutUint64(sb, uint64(realsize))

				endbuffer := new(bytes.Buffer)

				if writeintegrity {

					var readbuffer bytes.Buffer
					tee := io.TeeReader(rawbuffer, &readbuffer)

					crcdata := new(bytes.Buffer)

					_, err = crcdata.ReadFrom(tee)
					if err != nil && err != io.EOF {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t read tee crc data error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t read tee crc data error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					wcrc = crc32.Checksum(crcdata.Bytes(), ctbl32)

					head := Header{
						Size: uint64(realsize), Date: uint64(sec), Mode: uint16(vfilemode), Uuid: uint16(Uid), Guid: uint16(Gid), Comp: uint8(0), Encr: uint8(0), Crcs: wcrc, Rsvr: uint64(0),
					}

					err = binary.Write(endbuffer, Endian, head)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write binary header data to db error | File [%s] | DB [%s] | Header [%v] | %v", vhost, ip, file, dbf, head, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Write binary header data to db error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					_, err = endbuffer.ReadFrom(&readbuffer)
					if err != nil && err != io.EOF {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t read readbuffer data error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t read readbuffer data error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				} else {

					head := Header{
						Size: uint64(realsize), Date: uint64(sec), Mode: uint16(vfilemode), Uuid: uint16(Uid), Guid: uint16(Gid), Comp: uint8(0), Encr: uint8(0), Crcs: wcrc, Rsvr: uint64(0),
					}

					err = binary.Write(endbuffer, Endian, head)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write binary header data to db error | File [%s] | DB [%s] | Header [%v] | %v", vhost, ip, file, dbf, head, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Write binary header data to db error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					_, err = endbuffer.ReadFrom(rawbuffer)
					if err != nil && err != io.EOF {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t read rawbuffer data error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t read rawbuffer data error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				}

				err = db.Update(func(tx *bolt.Tx) error {

					verr := errors.New("bucket not exists")

					b := tx.Bucket([]byte(bucket))
					if b != nil {
						err = b.Put([]byte(file), endbuffer.Bytes())
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
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t write a file to db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t write a file to db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
						err = b.Put([]byte(file), []byte(bucket))
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
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t write key to index db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t write key to index db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
						err = b.Put([]byte(file), sb)
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
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t write key to size db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t write key to size db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
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
						err = b.Put([]byte(file), tb)
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
					putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t write key to time db bucket error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

					if debugmode {

						_, err = ctx.WriteString("[ERRO] Can`t write key to time db bucket error\n")
						if err != nil {
							putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
						}

					}

					db.Close()
					keymutex.Unlock(dbf)
					return

				}

				if writeintegrity {

					var pdata []byte

					err = db.View(func(tx *bolt.Tx) error {

						verr := errors.New("bucket not exists")

						b := tx.Bucket([]byte(bucket))
						if b != nil {
							pdata = b.Get([]byte(file))
							return nil
						} else {
							return verr
						}

					})
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t get data by key from db error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t get data by key from db error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					pread := bytes.NewReader(pdata)

					var readhead Header

					headbuffer := make([]byte, 36)

					hsizebuffer, err := pread.Read(headbuffer)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Read binary header data from db error | File [%s] | DB [%s] | Header Buffer [%p] | %v", vhost, ip, file, dbf, headbuffer, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Read binary header data from db error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					hread := bytes.NewReader(headbuffer[:hsizebuffer])

					err = binary.Read(hread, Endian, &readhead)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Read binary header data from db error | File [%s] | DB [%s] | Header Buffer [%p] | %v", vhost, ip, file, dbf, hread, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Read binary header data from db error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					rcrcdata := new(bytes.Buffer)

					_, err = rcrcdata.ReadFrom(pread)
					if err != nil && err != io.EOF {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Can`t read pread data error | File [%s] | DB [%s] | %v", vhost, ip, file, dbf, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Can`t read pread data error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					rcrc = crc32.Checksum(rcrcdata.Bytes(), ctbl32)

					rcrcdata.Reset()

					if wcrc != rcrc {

						fmt.Printf("CRC read file error | File [%s] | DB [%s] | Have CRC [%v] | Awaiting CRC [%v]\n", file, dbf, rcrc, wcrc)
						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | CRC read file error | File [%s] | DB [%s] | Have CRC [%v] | Awaiting CRC [%v]", vhost, ip, file, dbf, rcrc, wcrc)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] CRC read file error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				}

				if search {

					var nval RawKeysData
					var prnt uint64 = 0

					fname := filepath.Base(dbf)

					dcrc := crc64.Checksum([]byte(ddir), ctbl64)

					radix.Lock()
					tree, _, _ = tree.Insert([]byte(ddir), dcrc)
					radix.Unlock()

					nbucket := strconv.FormatUint(dcrc, 16)

					nkey := []byte("b:" + file)

					if strings.ContainsRune(fname, 95) {
						prnt, _ = strconv.ParseUint(strings.Split(strings.TrimSuffix(fname, ".bolt"), "_")[1], 10, 64)
					}

					nbck, _ := strconv.Atoi(strings.TrimPrefix(bucket, "wzd"))

					nval.Size = uint64(realsize)
					nval.Date = uint64(sec)
					nval.Prnt = uint32(prnt)
					nval.Buck = uint16(nbck)
					nval.Type = uint16(1)

					nbuffer := new(bytes.Buffer)

					_ = binary.Write(nbuffer, Endian, nval)

					err = NDBInsert(ndb, nbucket, nkey, nbuffer.Bytes(), 0)
					if err != nil {

						ctx.StatusCode(iris.StatusInternalServerError)
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 500 | Write file metadata to search db error | File [%s] | DB [%s] | NDB Bucket [%s] | %v", vhost, ip, file, dbf, nbucket, err)

						if debugmode {

							_, err = ctx.WriteString("[ERRO] Write file metadata to search db error\n")
							if err != nil {
								putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
							}

						}

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

				}

				if keyexists != "" && compaction && cmpsched || compact {

					if compact {

						err = db.CompactQuietly()
						if err != nil {
							putLogger.Errorf("| On the fly compaction error | DB [%s] | %v", dbf, err)
						}

						err = os.Chmod(dbf, filemode)
						if err != nil {
							putLogger.Errorf("Can`t chmod db error | DB [%s] | %v", dbf, err)
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

						putLogger.Errorf("| Gob encode for compaction db error | Path [%s] | %v", dbf, err)

						db.Close()
						keymutex.Unlock(dbf)
						return

					}

					err = NDBInsert(cdb, cmpbucket, bdbf, bval.Bytes(), 0)
					if err != nil {

						putLogger.Errorf("| Insert/Update data error | Path [%s] | %v", dbf, err)
						putLogger.Errorf("| Compaction will be started on the fly | DB [%s]", dbf)

						err = db.CompactQuietly()
						if err != nil {
							putLogger.Errorf("| On the fly compaction error | DB [%s] | %v", dbf, err)
						}

						err = os.Chmod(dbf, filemode)
						if err != nil {
							putLogger.Errorf("Can`t chmod db error | DB [%s] | %v", dbf, err)
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

				ctx.StatusCode(iris.StatusServiceUnavailable)
				putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 503 | Timeout mmutex lock error | File [%s] | DB [%s]", vhost, ip, file, dbf)

				if debugmode {

					_, err = ctx.WriteString("[ERRO] Timeout mmutex lock error\n")
					if err != nil {
						putLogger.Errorf("| Virtual Host [%s] | Client IP [%s] | 499 | Can`t complete response to client | %v", vhost, ip, err)
					}

				}

				return

			}

		}

	}

}
