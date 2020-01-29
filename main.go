package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/eltaline/badgerhold"
	"github.com/eltaline/mmutex"
	"github.com/eltaline/toml"
	"github.com/kataras/iris"
	"github.com/kataras/iris/middleware/logger"
	"github.com/kataras/iris/middleware/recover"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// Global Configuration

// Config : Global configuration type
type Config struct {
	Global global
	Server map[string]server
}

type global struct {
	BINDADDR          string
	BINDADDRSSL       string
	ONLYSSL           bool
	READTIMEOUT       int
	READHEADERTIMEOUT int
	WRITETIMEOUT      int
	IDLETIMEOUT       int
	KEEPALIVE         bool
	REALHEADER        string
	CHARSET           string
	DEBUGMODE         bool
	FREELIST          string
	PIDFILE           string
	LOGDIR            string
	LOGMODE           uint32
	DEFSLEEP          int
	CMPSCHED          bool
	CMPTHREADS        int
	CMPDIR            string
	CMPTIME           int
	CMPCHECK          int
}

type server struct {
	HOST           string
	ROOT           string
	SSLCRT         string
	SSLKEY         string
	GETALLOW       string
	PUTALLOW       string
	DELALLOW       string
	OPTIONS        string
	HEADORIGIN     string
	XFRAME         string
	UPLOAD         bool
	DELETE         bool
	COMPACTION     bool
	GETBOLT        bool
	GETKEYS        bool
	GETINFO        bool
	GETCOUNT       bool
	NONUNIQUE      bool
	WRITEINTEGRITY bool
	READINTEGRITY  bool
	TRYTIMES       int
	OPENTRIES      int
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
	GZSTATIC       bool
	LOG4XX         bool
}

// Header : type contains binary header fields
type Header struct {
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

// ReqRange : type contains start and length number of bytes for range GET requests
type ReqRange struct {
	start  int64
	length int64
}

// Compact : type contains information about db files for compaction/defragmentation
type Compact struct {
	Path   string
	MachID string
	Time   time.Time
}

// Allow : type for key and slice pairs of a virtual host and CIDR allowable networks
type Allow struct {
	Vhost string
	CIDR  []strCIDR
}

type strCIDR struct {
	Addr string
}

// KeysInfo : type for files and/or keys with info
type KeysInfo struct {
	Key  string `json:"key"`
	Size uint64  `json:"size"`
	Date uint32  `json:"date"`
	Type int    `json:"type"`
}

// Global Variables

var (
	// Endian global variable
	Endian binary.ByteOrder

	// Uid : System user UID
	Uid int64
	// Gid : System user GID
	Gid int64

	config     Config
	configfile string = "/etc/wzd/wzd.conf"
	wg         sync.WaitGroup

	onlyssl bool = false

	getallow []Allow
	putallow []Allow
	delallow []Allow

	readtimeout       time.Duration = 60 * time.Second
	readheadertimeout time.Duration = 5 * time.Second
	writetimeout      time.Duration = 60 * time.Second
	idletimeout       time.Duration = 60 * time.Second
	keepalive         bool          = false

	machid string = "nomachineid"

	shutdown  bool = false
	wshutdown bool = false

	debugmode bool = false

	freelist string = "hashmap"

	pidfile string = "/run/wzd/wzd.pid"

	logdir  string = "/var/log/wzd"
	logmode os.FileMode

	defsleep time.Duration = 1 * time.Second

	cmpsched bool          = true
	cmpdir   string        = "/var/lib/wzd"
	cmptime  int           = 30
	cmpcheck time.Duration = 300 * time.Second

	rgxbolt    = regexp.MustCompile(`(\.bolt$)`)
	rgxcrcbolt = regexp.MustCompile(`(\.crcbolt$)`)
	rgxctype   = regexp.MustCompile("(multipart)")
)

// Init Function

func init() {

	var version string = "1.1.2"
	var vprint bool = false
	var help bool = false

	// Command Line Options

	flag.StringVar(&configfile, "config", configfile, "--config=/etc/wzd/wzd.conf")
	flag.BoolVar(&debugmode, "debug", debugmode, "--debug - debug mode")
	flag.BoolVar(&vprint, "version", vprint, "--version - print version")
	flag.BoolVar(&help, "help", help, "--help - displays help")

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

	rgxonlyssl := regexp.MustCompile("^(?i)(true|false)$")
	mchonlyssl := rgxonlyssl.MatchString(fmt.Sprintf("%t", config.Global.ONLYSSL))
	Check(mchonlyssl, "[global]", "onlyssl", fmt.Sprintf("%t", config.Global.ONLYSSL), "true or false", DoExit)

	mchreadtimeout := RBInt(config.Global.READTIMEOUT, 0, 86400)
	Check(mchreadtimeout, "[global]", "readtimeout", fmt.Sprintf("%d", config.Global.READTIMEOUT), "from 0 to 86400", DoExit)

	mchreadheadertimeout := RBInt(config.Global.READHEADERTIMEOUT, 0, 86400)
	Check(mchreadheadertimeout, "[global]", "readheadertimeout", fmt.Sprintf("%d", config.Global.READHEADERTIMEOUT), "from 0 to 86400", DoExit)

	mchwritetimeout := RBInt(config.Global.WRITETIMEOUT, 0, 86400)
	Check(mchwritetimeout, "[global]", "writetimeout", fmt.Sprintf("%d", config.Global.WRITETIMEOUT), "from 0 to 86400", DoExit)

	mchidletimeout := RBInt(config.Global.IDLETIMEOUT, 0, 86400)
	Check(mchidletimeout, "[global]", "idletimeout", fmt.Sprintf("%d", config.Global.IDLETIMEOUT), "from 0 to 86400", DoExit)

	rgxkeepalive := regexp.MustCompile("^(?i)(true|false)$")
	mchkeepalive := rgxkeepalive.MatchString(fmt.Sprintf("%t", config.Global.KEEPALIVE))
	Check(mchkeepalive, "[global]", "keepalive", fmt.Sprintf("%t", config.Global.KEEPALIVE), "true or false", DoExit)

	if config.Global.REALHEADER != "" {
		rgxrealheader := regexp.MustCompile("^([a-zA-Z0-9-_]+)")
		mchrealheader := rgxrealheader.MatchString(config.Global.REALHEADER)
		Check(mchrealheader, "[global]", "realheader", config.Global.REALHEADER, "ex. X-Real-IP", DoExit)
	} else {
		config.Global.REALHEADER = "X-Real-IP"
	}

	if config.Global.CHARSET != "" {
		rgxcharset := regexp.MustCompile("^([a-zA-Z0-9-])+")
		mchcharset := rgxcharset.MatchString(config.Global.CHARSET)
		Check(mchcharset, "[global]", "charset", config.Global.CHARSET, "ex. UTF-8", DoExit)
	} else {
		config.Global.CHARSET = "UTF-8"
	}

	rgxdebugmode := regexp.MustCompile("^(?i)(true|false)$")
	mchdebugmode := rgxdebugmode.MatchString(fmt.Sprintf("%t", config.Global.DEBUGMODE))
	Check(mchdebugmode, "[global]", "debugmode", fmt.Sprintf("%t", config.Global.DEBUGMODE), "true or false", DoExit)

	if config.Global.FREELIST != "" {
		rgxfreelist := regexp.MustCompile("^(?i)(hashmap|array)$")
		mchfreelist := rgxfreelist.MatchString(config.Global.FREELIST)
		Check(mchfreelist, "[global]", "freelist", config.Global.FREELIST, "hashmap or array", DoExit)
	} else {
		config.Global.FREELIST = "hashmap"
	}

	if config.Global.PIDFILE != "" {
		rgxpidfile := regexp.MustCompile("^(/?[^/\x00]*)+/?$")
		mchpidfile := rgxpidfile.MatchString(config.Global.PIDFILE)
		Check(mchpidfile, "[global]", "pidfile", config.Global.PIDFILE, "ex. /run/wzd/wzd.pid", DoExit)
	} else {
		config.Global.PIDFILE = "/run/wzd/wzd.pid"
	}

	if config.Global.LOGDIR != "" {
		rgxlogdir := regexp.MustCompile("^(/?[^/\x00]*)+/?$")
		mchlogdir := rgxlogdir.MatchString(config.Global.LOGDIR)
		Check(mchlogdir, "[global]", "logdir", config.Global.LOGDIR, "ex. /var/log/wzd", DoExit)
	} else {
		config.Global.LOGDIR = "/var/log/wzd"
	}

	rgxlogmode := regexp.MustCompile("^([0-7]{3})")
	mchlogmode := rgxlogmode.MatchString(fmt.Sprintf("%d", config.Global.LOGMODE))
	Check(mchlogmode, "[global]", "logmode", fmt.Sprintf("%d", config.Global.LOGMODE), "from 0600 to 0666", DoExit)

	mchdefsleep := RBInt(config.Global.DEFSLEEP, 1, 5)
	Check(mchdefsleep, "[global]", "defsleep", fmt.Sprintf("%d", config.Global.DEFSLEEP), "from 1 to 5", DoExit)

	if config.Global.CMPDIR != "" {
		rgxcmpdir := regexp.MustCompile("^(/?[^/\x00]*)+/?$")
		mchcmpdir := rgxcmpdir.MatchString(config.Global.CMPDIR)
		Check(mchcmpdir, "[global]", "cmpdir", config.Global.CMPDIR, "ex. /var/lib/wzd", DoExit)
	} else {
		config.Global.CMPDIR = "/var/lib/wzd"
	}

	rgxcmpsched := regexp.MustCompile("^(?i)(true|false)$")
	mchcmpsched := rgxcmpsched.MatchString(fmt.Sprintf("%t", config.Global.CMPSCHED))
	Check(mchcmpsched, "[global]", "cmpsched", fmt.Sprintf("%t", config.Global.CMPSCHED), "true or false", DoExit)

	if config.Global.CMPSCHED {

		mchcmptime := RBInt(config.Global.CMPTIME, 1, 365)
		Check(mchcmptime, "[global]", "cmptime", fmt.Sprintf("%d", config.Global.CMPTIME), "from 1 to 365", DoExit)

		mchcmpcheck := RBInt(config.Global.CMPCHECK, 1, 5)
		Check(mchcmpcheck, "[global]", "cmpcheck", fmt.Sprintf("%d", config.Global.CMPCHECK), "from 1 to 5", DoExit)

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

	appLogger, applogfile := AppLogger()
	defer applogfile.Close()

	appLogger.Warnf("| Starting wZD Server [%s]", version)

	switch {
	case config.Global.FREELIST == "hashmap":
		appLogger.Warnf("| Freelist Mode [HASHMAP]")
	case config.Global.FREELIST == "array":
		appLogger.Warnf("| Freelist Mode [ARRAY]")
	}

	switch {
	case config.Global.ONLYSSL:
		appLogger.Warnf("| Only SSL Mode [ENABLED]")
	default:
		appLogger.Warnf("| Only SSL Mode [DISABLED]")
	}

	switch {
	case config.Global.CMPSCHED:
		appLogger.Warnf("| Compaction Scheduler [ENABLED]")
		appLogger.Warnf("| Compaction Time > [%d] days", config.Global.CMPTIME)
		appLogger.Warnf("| Compaction Scheduler Check Every [%d] seconds", config.Global.CMPCHECK)
	default:
		appLogger.Warnf("| Compaction Scheduler [DISABLED]")
	}

	switch {
	case config.Global.KEEPALIVE:
		appLogger.Warnf("| KeepAlive [ENABLED]")
	default:
		appLogger.Warnf("| KeepAlive [DISABLED]")
	}

	// Check Server Options

	var section string

	rgxroot := regexp.MustCompile("^(/[^/\x00]*)+/?$")
	rgxsslcrt := regexp.MustCompile("^(/?[^/\x00]*)+/?$")
	rgxsslkey := regexp.MustCompile("^(/?[^/\x00]*)+/?$")
	rgxupload := regexp.MustCompile("^(?i)(true|false)$")
	rgxdelete := regexp.MustCompile("^(?i)(true|false)$")
	rgxcompaction := regexp.MustCompile("^(?i)(true|false)$")
	rgxgetbolt := regexp.MustCompile("^(?i)(true|false)$")
	rgxgetkeys := regexp.MustCompile("^(?i)(true|false)$")
	rgxgetinfo := regexp.MustCompile("^(?i)(true|false)$")
	rgxgetcount := regexp.MustCompile("^(?i)(true|false)$")
	rgxnonunique := regexp.MustCompile("^(?i)(true|false)$")
	rgxwriteintegrity := regexp.MustCompile("^(?i)(true|false)$")
	rgxreadintegrity := regexp.MustCompile("^(?i)(true|false)$")
	rgxargs := regexp.MustCompile("^(?i)(true|false)$")
	rgxfilemode := regexp.MustCompile("^([0-7]{3})")
	rgxdirmode := regexp.MustCompile("^([0-7]{3})")
	rgxdelbolt := regexp.MustCompile("^(?i)(true|false)$")
	rgxdeldir := regexp.MustCompile("^(?i)(true|false)$")
	rgxgzstatic := regexp.MustCompile("^(?i)(true|false)$")
	rgxlog4xx := regexp.MustCompile("^(?i)(true|false)$")

	for _, Server := range config.Server {

		section = "[server] | Host ["
		section = fmt.Sprintf("%s%s%s", section, Server.HOST, "]")

		if Server.HOST == "" {
			fmt.Printf("Server host cannot be empty error | %s%s\n", section, " | ex. host=\"localhost\"")
			os.Exit(1)
		}

		mchroot := rgxroot.MatchString(Server.ROOT)
		Check(mchroot, section, "root", Server.ROOT, "ex. /var/storage/localhost", DoExit)

		if Server.SSLCRT != "" {
			mchsslcrt := rgxsslcrt.MatchString(Server.SSLCRT)
			Check(mchsslcrt, section, "sslcrt", Server.SSLCRT, "/path/to/sslcrt.pem", DoExit)

			if Server.SSLKEY == "" {
				appLogger.Errorf("| SSL key cannot be empty error | %s | File [%s]", section, Server.SSLKEY)
				fmt.Printf("SSL key cannot be empty error | %s | File [%s]\n", section, Server.SSLKEY)
				os.Exit(1)
			}

			if !FileOrLinkExists(Server.SSLCRT) {
				appLogger.Errorf("| SSL certificate not exists/permission denied error | %s | File [%s]", section, Server.SSLCRT)
				fmt.Printf("SSL certificate not exists/permission denied error | %s | File [%s]\n", section, Server.SSLCRT)
				os.Exit(1)
			}

		}

		if Server.SSLKEY != "" {
			mchsslkey := rgxsslkey.MatchString(Server.SSLKEY)
			Check(mchsslkey, section, "sslkey", Server.SSLKEY, "/path/to/sslkey.pem", DoExit)

			if Server.SSLCRT == "" {
				appLogger.Errorf("| SSL certificate cannot be empty error | %s | File [%s]", section, Server.SSLCRT)
				fmt.Printf("SSL certificate cannot be empty error | %s | File [%s]\n", section, Server.SSLCRT)
				os.Exit(1)
			}

			if !FileOrLinkExists(Server.SSLKEY) {
				appLogger.Errorf("| SSL key not exists/permission denied error | %s | File [%s]", section, Server.SSLKEY)
				fmt.Printf("SSL key not exists/permission denied error | %s | File [%s]\n", section, Server.SSLKEY)
				os.Exit(1)
			}

		}

		if Server.GETALLOW != "" {

			var get Allow

			getfile, err := os.OpenFile(Server.GETALLOW, os.O_RDONLY, os.ModePerm)
			if err != nil {
				appLogger.Errorf("Can`t open get allow file error | %s | File [%s] | %v", section, Server.GETALLOW, err)
				fmt.Printf("Can`t open get allow file error | %s | File [%s] | %v\n", section, Server.GETALLOW, err)
				os.Exit(1)
			}
			// No need to defer in loop

			get.Vhost = Server.HOST

			sgetallow := bufio.NewScanner(getfile)
			for sgetallow.Scan() {

				line := sgetallow.Text()

				_, _, err := net.ParseCIDR(line)
				if err != nil {
					appLogger.Errorf("| Bad CIDR line format in a get allow file error | %s | File [%s] | Line [%s]", section, Server.GETALLOW, line)
					fmt.Printf("Bad CIDR line format in a get allow file error | %s | File [%s] | Line [%s]\n", section, Server.GETALLOW, line)
					os.Exit(1)
				}

				get.CIDR = append(get.CIDR, struct{ Addr string }{line})

			}

			err = getfile.Close()
			if err != nil {
				appLogger.Errorf("Close after read get allow file error | %s | File [%s] | %v\n", section, Server.GETALLOW, err)
				fmt.Printf("Close after read get allow file error | %s | File [%s] | %v\n", section, Server.GETALLOW, err)
				os.Exit(1)
			}

			err = sgetallow.Err()
			if err != nil {
				fmt.Printf("Read lines from a get allow file error | %s | File [%s] | %v\n", section, Server.GETALLOW, err)
				return
			}

			getallow = append(getallow, get)

		}

		if Server.PUTALLOW != "" {

			var put Allow

			putfile, err := os.OpenFile(Server.PUTALLOW, os.O_RDONLY, os.ModePerm)
			if err != nil {
				appLogger.Errorf("Can`t open put allow file error | %s | File [%s] | %v", section, Server.PUTALLOW, err)
				fmt.Printf("Can`t open put allow file error | %s | File [%s] | %v\n", section, Server.PUTALLOW, err)
				os.Exit(1)
			}
			// No need to defer in loop

			put.Vhost = Server.HOST

			sputallow := bufio.NewScanner(putfile)
			for sputallow.Scan() {

				line := sputallow.Text()

				_, _, err := net.ParseCIDR(line)
				if err != nil {
					appLogger.Errorf("| Bad CIDR line format in put allow file error | %s | File [%s] | Line [%s]", section, Server.PUTALLOW, line)
					fmt.Printf("Bad CIDR line format in put allow file error | %s | File [%s] | Line [%s]\n", section, Server.PUTALLOW, line)
					os.Exit(1)
				}

				put.CIDR = append(put.CIDR, struct{ Addr string }{line})

			}

			err = putfile.Close()
			if err != nil {
				appLogger.Errorf("Close after read put allow file error | %s | File [%s] | %v\n", section, Server.PUTALLOW, err)
				fmt.Printf("Close after read put allow file error | %s | File [%s] | %v\n", section, Server.PUTALLOW, err)
				os.Exit(1)
			}

			err = sputallow.Err()
			if err != nil {
				fmt.Printf("Read lines from put allow file error | %s | File [%s] | %v\n", section, Server.PUTALLOW, err)
				return
			}

			putallow = append(putallow, put)

		}

		if Server.DELALLOW != "" {

			var del Allow

			delfile, err := os.OpenFile(Server.DELALLOW, os.O_RDONLY, os.ModePerm)
			if err != nil {
				appLogger.Errorf("Can`t open del allow file error | %s | File [%s] | %v", section, Server.DELALLOW, err)
				fmt.Printf("Can`t open del allow file error | %s | File [%s] | %v\n", section, Server.DELALLOW, err)
				os.Exit(1)
			}
			// No need to defer in loop

			del.Vhost = Server.HOST

			sdelallow := bufio.NewScanner(delfile)
			for sdelallow.Scan() {

				line := sdelallow.Text()

				_, _, err := net.ParseCIDR(line)
				if err != nil {
					appLogger.Errorf("| Bad CIDR line format in a del allow file error | %s | File [%s] | Line [%s]", section, Server.DELALLOW, line)
					fmt.Printf("Bad CIDR line format in a del allow file error | %s | File [%s] | Line [%s]\n", section, Server.DELALLOW, line)
					os.Exit(1)
				}

				del.CIDR = append(del.CIDR, struct{ Addr string }{line})

			}

			err = delfile.Close()
			if err != nil {
				appLogger.Errorf("Close after read del allow file error | %s | File [%s] | %v\n", section, Server.DELALLOW, err)
				fmt.Printf("Close after read del allow file error | %s | File [%s] | %v\n", section, Server.DELALLOW, err)
				os.Exit(1)
			}

			err = sdelallow.Err()
			if err != nil {
				fmt.Printf("Read lines from a del allow file error | %s | File [%s] | %v\n", section, Server.DELALLOW, err)
				return
			}

			delallow = append(delallow, del)

		}

		mchupload := rgxupload.MatchString(fmt.Sprintf("%t", Server.UPLOAD))
		Check(mchupload, section, "upload", fmt.Sprintf("%t", Server.UPLOAD), "true or false", DoExit)

		mchdelete := rgxdelete.MatchString(fmt.Sprintf("%t", Server.DELETE))
		Check(mchdelete, section, "delete", fmt.Sprintf("%t", Server.DELETE), "true or false", DoExit)

		mchcompaction := rgxcompaction.MatchString(fmt.Sprintf("%t", Server.COMPACTION))
		Check(mchcompaction, section, "compaction", fmt.Sprintf("%t", Server.COMPACTION), "true or false", DoExit)

		mchgetbolt := rgxgetbolt.MatchString(fmt.Sprintf("%t", Server.GETBOLT))
		Check(mchgetbolt, section, "getbolt", fmt.Sprintf("%t", Server.GETBOLT), "true or false", DoExit)

		mchgetkeys := rgxgetkeys.MatchString(fmt.Sprintf("%t", Server.GETKEYS))
		Check(mchgetkeys, section, "getkeys", fmt.Sprintf("%t", Server.GETKEYS), "true or false", DoExit)

		mchgetinfo := rgxgetinfo.MatchString(fmt.Sprintf("%t", Server.GETINFO))
		Check(mchgetinfo, section, "getinfo", fmt.Sprintf("%t", Server.GETINFO), "true or false", DoExit)

		mchgetcount := rgxgetcount.MatchString(fmt.Sprintf("%t", Server.GETCOUNT))
		Check(mchgetcount, section, "getcount", fmt.Sprintf("%t", Server.GETCOUNT), "true or false", DoExit)

		mchnonunique := rgxnonunique.MatchString(fmt.Sprintf("%t", Server.NONUNIQUE))
		Check(mchnonunique, section, "nonunique", fmt.Sprintf("%t", Server.NONUNIQUE), "true or false", DoExit)

		mchwriteintegrity := rgxwriteintegrity.MatchString(fmt.Sprintf("%t", Server.WRITEINTEGRITY))
		Check(mchwriteintegrity, section, "writeintegrity", fmt.Sprintf("%t", Server.WRITEINTEGRITY), "true or false", DoExit)

		mchreadintegrity := rgxreadintegrity.MatchString(fmt.Sprintf("%t", Server.READINTEGRITY))
		Check(mchreadintegrity, section, "readintegrity", fmt.Sprintf("%t", Server.READINTEGRITY), "true or false", DoExit)

		mchtrytimes := RBInt(Server.TRYTIMES, 1, 1000)
		Check(mchtrytimes, section, "trytimes", fmt.Sprintf("%d", Server.TRYTIMES), "from 1 to 1000", DoExit)

		mchopentries := RBInt(Server.OPENTRIES, 1, 1000)
		Check(mchopentries, section, "opentries", fmt.Sprintf("%d", Server.OPENTRIES), "from 1 to 1000", DoExit)

		mchlocktimeout := RBInt(Server.LOCKTIMEOUT, 1, 3600)
		Check(mchlocktimeout, section, "locktimeout", fmt.Sprintf("%d", Server.LOCKTIMEOUT), "from 1 to 3600", DoExit)

		mchfmaxsize := RBInt64(Server.FMAXSIZE, 1, 33554432)
		Check(mchfmaxsize, section, "fmaxsize", fmt.Sprintf("%d", Server.FMAXSIZE), "from 1 to 33554432", DoExit)

		mchargs := rgxargs.MatchString(fmt.Sprintf("%t", Server.ARGS))
		Check(mchargs, section, "args", fmt.Sprintf("%t", Server.ARGS), "true or false", DoExit)

		mchcctrl := RBInt(Server.CCTRL, 0, 2147483647)
		Check(mchcctrl, section, "cctrl", fmt.Sprintf("%d", Server.CCTRL), "from 0 to 2147483647", DoExit)

		mchminbuffer := RBInt64(Server.MINBUFFER, 4096, 524288)
		Check(mchminbuffer, section, "minbuffer", fmt.Sprintf("%d", Server.MINBUFFER), "from 4096 to 524288", DoExit)

		mchlowbuffer := RBInt64(Server.LOWBUFFER, 1048576, 33554432)
		Check(mchlowbuffer, section, "lowbuffer", fmt.Sprintf("%d", Server.LOWBUFFER), "from 1048576 to 33554432", DoExit)

		mchmedbuffer := RBInt64(Server.MEDBUFFER, 67108864, 268169216)
		Check(mchmedbuffer, section, "medbuffer", fmt.Sprintf("%d", Server.MEDBUFFER), "from 67108864 to 268169216", DoExit)

		mchbigbuffer := RBInt64(Server.BIGBUFFER, 536870912, 2147483647)
		Check(mchbigbuffer, section, "bigbuffer", fmt.Sprintf("%d", Server.BIGBUFFER), "from 536870912 to 2147483647", DoExit)

		mchfilemode := rgxfilemode.MatchString(fmt.Sprintf("%d", Server.FILEMODE))
		Check(mchfilemode, section, "filemode", fmt.Sprintf("%d", Server.FILEMODE), "from 0600 to 0666", DoExit)

		mchdirmode := rgxdirmode.MatchString(fmt.Sprintf("%d", Server.DIRMODE))
		Check(mchdirmode, section, "dirmode", fmt.Sprintf("%d", Server.DIRMODE), "from 0700 to 0777", DoExit)

		mchdelbolt := rgxdelbolt.MatchString(fmt.Sprintf("%t", Server.DELBOLT))
		Check(mchdelbolt, section, "delbolt", fmt.Sprintf("%t", Server.DELBOLT), "true or false", DoExit)

		mchdeldir := rgxdeldir.MatchString(fmt.Sprintf("%t", Server.DELDIR))
		Check(mchdeldir, section, "deldir", fmt.Sprintf("%t", Server.DELDIR), "true or false", DoExit)

		mchgzstatic := rgxgzstatic.MatchString(fmt.Sprintf("%t", Server.GZSTATIC))
		Check(mchgzstatic, section, "gzstatic", fmt.Sprintf("%t", Server.GZSTATIC), "true or false", DoExit)

		mchlog4xx := rgxlog4xx.MatchString(fmt.Sprintf("%t", Server.LOG4XX))
		Check(mchlog4xx, section, "log4xx", fmt.Sprintf("%t", Server.LOG4XX), "true or false", DoExit)

		// Output Important Server Configuration Options

		appLogger.Warnf("| Host [%s] | Max File Size [%d]", Server.HOST, Server.FMAXSIZE)

		switch {
		case Server.UPLOAD:
			appLogger.Warnf("| Host [%s] | Upload [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Upload [DISABLED]", Server.HOST)
		}

		switch {
		case Server.DELETE:
			appLogger.Warnf("| Host [%s] | Delete [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Delete [DISABLED]", Server.HOST)
		}

		switch {
		case Server.COMPACTION && config.Global.CMPSCHED:
			appLogger.Warnf("| Host [%s] | Compaction [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Compaction [DISABLED]", Server.HOST)
		}

		switch {
		case Server.WRITEINTEGRITY:
			appLogger.Warnf("| Host [%s] | Write Integrity [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Write Integrity [DISABLED]", Server.HOST)
		}

		switch {
		case Server.READINTEGRITY:
			appLogger.Warnf("| Host [%s] | Read Integrity [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Read Integrity [DISABLED]", Server.HOST)
		}

		switch {
		case Server.ARGS:
			appLogger.Warnf("| Host [%s] | Query Arguments [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Query Arguments [DISABLED]", Server.HOST)
		}

		switch {
		case Server.GETBOLT:
			appLogger.Warnf("| Host [%s] | Get Bolt Files [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Get Bolt Files [DISABLED]", Server.HOST)
		}

		switch {
		case Server.GETKEYS:
			appLogger.Warnf("| Host [%s] | Get Names Keys/Files [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Get Names Keys/Files [DISABLED]", Server.HOST)
		}

		switch {
		case Server.GETINFO:
			appLogger.Warnf("| Host [%s] | Get Info Keys/Files [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Get Info Keys/Files [DISABLED]", Server.HOST)
		}

		switch {
		case Server.GETCOUNT:
			appLogger.Warnf("| Host [%s] | Get Count Keys/Files [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Get Count Keys/Files [DISABLED]", Server.HOST)
		}

		switch {
		case Server.NONUNIQUE:
			appLogger.Warnf("| Host [%s] | Non-Unique Keys/Files [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Non-Unique Keys/Files [DISABLED]", Server.HOST)
		}

		appLogger.Warnf("| Host [%s] | Cache-Control Time [%d]", Server.HOST, Server.CCTRL)

		switch {
		case Server.DELBOLT:
			appLogger.Warnf("| Host [%s] | Delete Bolt Files [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Delete Bolt Files [DISABLED]", Server.HOST)
		}

		switch {
		case Server.DELDIR:
			appLogger.Warnf("| Host [%s] | Delete Directory [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Delete Directory [DISABLED]", Server.HOST)
		}

		switch {
		case Server.GZSTATIC:
			appLogger.Warnf("| Host [%s] | Static GZIP [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Static GZIP [DISABLED]", Server.HOST)
		}

		switch {
		case Server.LOG4XX:
			appLogger.Warnf("| Host [%s] | Logging 4XX Errors [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Logging 4XX Errors [DISABLED]", Server.HOST)
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

	if !DirExists(logdir) {
		fmt.Printf("Log directory not exists error | Path: [%s]\n", logdir)
		os.Exit(1)
	}

	appLogger, applogfile := AppLogger()
	defer applogfile.Close()

	// PID File

	pidfile = config.Global.PIDFILE

	switch {
	case FileExists(pidfile):
		err := os.Remove(pidfile)
		if err != nil {
			appLogger.Errorf("| Can`t remove pid file error | File [%s] | %v", pidfile, err)
			fmt.Printf("Can`t remove pid file error | File [%s] | %v\n", pidfile, err)
			os.Exit(1)
		}
		fallthrough
	default:
		err := ioutil.WriteFile(pidfile, []byte(fpid), 0644)
		if err != nil {
			appLogger.Errorf("| Can`t create pid file error | File [%s] | %v", pidfile, err)
			fmt.Printf("Can`t create pid file error | File [%s] | %v\n", pidfile, err)
			os.Exit(1)
		}

	}

	// Only SSL

	onlyssl = config.Global.ONLYSSL

	// KeepAlive

	keepalive = config.Global.KEEPALIVE

	// Freelist

	freelist = config.Global.FREELIST

	// Default Timers / Tries

	defsleep = time.Duration(config.Global.DEFSLEEP) * time.Second

	// Pid Handling

	appLogger.Warnf("wZD server running with a pid: %s", gpid)

	// Map Mutex

	keymutex := mmutex.NewMMutex()

	// Open CMP DB

	cmpsched = config.Global.CMPSCHED
	cmpdir = config.Global.CMPDIR
	cmptime = config.Global.CMPTIME
	cmpcheck = time.Duration(config.Global.CMPCHECK) * time.Second

	options := badgerhold.DefaultOptions
	options.Dir = cmpdir
	options.ValueDir = cmpdir

	cdb, err := badgerhold.Open(options)
	if err != nil {
		appLogger.Errorf("| Can`t open/create compaction db | DB Directory [%s] | %v", cmpdir, err)
		os.Exit(1)
	}
	defer cdb.Close()

	// Go CMP Scheduler

	if cmpsched {
		go CMPScheduler(cdb, keymutex)
	}

	// Web Server

	app := iris.New()

	// Iris Startup Log Debug Options

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

	app.Get("/{directory:path}", ZDGet())
	app.Head("/{directory:path}", ZDGet())
	app.Options("/{directory:path}", ZDGet())
	app.Put("/{directory:path}", ZDPut(keymutex, cdb))
	app.Post("/{directory:path}", ZDPut(keymutex, cdb))
	app.Delete("/{directory:path}", ZDDel(keymutex, cdb))

	// Interrupt Handler

	iris.RegisterOnInterrupt(func() {

		// Shutdown Server

		appLogger.Warnf("Stop receive new requests")
		appLogger.Warnf("Capture interrupt")
		appLogger.Warnf("Notify go routines about interrupt")

		shutdown = true

		// Wait Go Routines

		appLogger.Warnf("Awaiting all go routines")

		wg.Wait()

		appLogger.Warnf("Finished all go routines")

		timeout := 5 * time.Second

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		appLogger.Warnf("Shutdown wZD server completed")

		err := app.Shutdown(ctx)
		if err != nil {
			fmt.Printf("Something wrong when shutdown wZD Server | %v\n", err)
			os.Exit(1)
		}

		// Remove PID File

		if FileExists(pidfile) {
			err := os.Remove(pidfile)
			if err != nil {
				appLogger.Errorf("| Can`t remove pid file error | File [%s] | %v", pidfile, err)
				fmt.Printf("Can`t remove pid file error | File [%s] | %v\n", pidfile, err)
				os.Exit(1)
			}
		}

	})

	// TLS Configuration

	var sstd bool = false
	var stls bool = false
	var stdcount int = 0
	var tlscount int = 0

	tlsConfig := &tls.Config{}

	for _, Server := range config.Server {

		if Server.SSLCRT != "" && Server.SSLKEY != "" {
			tlscount++
		}

		if !onlyssl {
			stdcount++
		}

	}

	if tlscount > 0 {

		tlsConfig.Certificates = make([]tls.Certificate, tlscount)

		s := 0

		for _, Server := range config.Server {

			if Server.SSLCRT != "" && Server.SSLKEY != "" {

				tlsConfig.Certificates[s], err = tls.LoadX509KeyPair(Server.SSLCRT, Server.SSLKEY)
				if err != nil {
					appLogger.Errorf("| Can`t apply ssl certificate/key error | Certificate [%s] | Key [%s] | %v", Server.SSLCRT, Server.SSLKEY, err)
					fmt.Printf("Can`t apply ssl certificate/key error | Certificate [%s] | Key [%s] | %v\n", Server.SSLCRT, Server.SSLKEY, err)
					os.Exit(1)
				}

				s++

			}

		}

		tlsConfig.BuildNameToCertificate()

		stls = true

	}

	if stdcount > 0 {
		sstd = true
	}

	// Configure App

	charset := config.Global.CHARSET
	realheader := config.Global.REALHEADER

	app.Configure(iris.WithoutInterruptHandler, iris.WithoutBodyConsumptionOnUnmarshal, iris.WithCharset(charset), iris.WithRemoteAddrHeader(realheader), iris.WithOptimizations, iris.WithConfiguration(iris.Configuration{
		DisablePathCorrection: false,
		EnablePathEscape:      true,
		TimeFormat:            "Mon, 02 Jan 2006 15:04:05 GMT",
		Charset:               charset,
	}))

	// Build App

	err = app.Build()
	if err != nil {
		fmt.Printf("Something wrong when building wZD Server | %v\n", err)
		os.Exit(1)
	}

	// Timeouts

	readtimeout = time.Duration(config.Global.READTIMEOUT) * time.Second
	readheadertimeout = time.Duration(config.Global.READHEADERTIMEOUT) * time.Second
	writetimeout = time.Duration(config.Global.WRITETIMEOUT) * time.Second
	idletimeout = time.Duration(config.Global.IDLETIMEOUT) * time.Second

	// Start WebServer

	switch {

	case sstd && !stls:

		bindaddr := config.Global.BINDADDR
		switch {
		case bindaddr == "":
			bindaddr = "127.0.0.1:9699"
		}

		srv := &http.Server{
			Addr:              bindaddr,
			ReadTimeout:       readtimeout,
			ReadHeaderTimeout: readheadertimeout,
			IdleTimeout:       idletimeout,
			WriteTimeout:      writetimeout,
			MaxHeaderBytes:    1 << 20,
		}

		srv.SetKeepAlivesEnabled(keepalive)

		err = app.Run(iris.Server(srv))
		if err != nil && !shutdown {
			fmt.Printf("Something wrong when starting wZD Server | %v\n", err)
			os.Exit(1)
		}

	case !sstd && stls:

		bindaddrssl := config.Global.BINDADDRSSL
		switch {
		case bindaddrssl == "":
			bindaddrssl = "127.0.0.1:9799"
		}

		srvssl := &http.Server{
			Addr:              bindaddrssl,
			ReadTimeout:       readtimeout,
			ReadHeaderTimeout: readheadertimeout,
			IdleTimeout:       idletimeout,
			WriteTimeout:      writetimeout,
			MaxHeaderBytes:    1 << 20,
			TLSConfig:         tlsConfig,
		}

		srvssl.SetKeepAlivesEnabled(keepalive)

		err = app.Run(iris.Server(srvssl))
		if err != nil && !shutdown {
			fmt.Printf("Something wrong when starting wZD Server | %v\n", err)
			os.Exit(1)
		}

	case sstd && stls:

		bindaddr := config.Global.BINDADDR
		switch {
		case bindaddr == "":
			bindaddr = "127.0.0.1:9699"
		}

		bindaddrssl := config.Global.BINDADDRSSL
		switch {
		case bindaddrssl == "":
			bindaddrssl = "127.0.0.1:9799"
		}

		srv := &http.Server{
			Handler:           app,
			Addr:              bindaddr,
			ReadTimeout:       readtimeout,
			ReadHeaderTimeout: readheadertimeout,
			IdleTimeout:       idletimeout,
			WriteTimeout:      writetimeout,
			MaxHeaderBytes:    1 << 20,
		}

		srvssl := &http.Server{
			Addr:              bindaddrssl,
			ReadTimeout:       readtimeout,
			ReadHeaderTimeout: readheadertimeout,
			IdleTimeout:       idletimeout,
			WriteTimeout:      writetimeout,
			MaxHeaderBytes:    1 << 20,
			TLSConfig:         tlsConfig,
		}

		srv.SetKeepAlivesEnabled(keepalive)
		srvssl.SetKeepAlivesEnabled(keepalive)

		go srv.ListenAndServe()

		if debugmode {
			appLogger.Debugf("Application: running using 1 host(s)")
			appLogger.Debugf("Host: addr is %s", bindaddr)
			appLogger.Debugf("Host: virtual host is %s", bindaddr)
			appLogger.Debugf("Host: register startup notifier")
			appLogger.Debugf("Now listening on: http://%s", bindaddr)
		} else {
			appLogger.Warnf("Now listening on: http://%s", bindaddr)
		}

		err = app.Run(iris.Server(srvssl))
		if err != nil && !shutdown {
			fmt.Printf("Something wrong when starting wZD Server | %v\n", err)
			os.Exit(1)
		}

	default:

		appLogger.Errorf("| Not configured any virtual host. Must check config [%s]", configfile)
		fmt.Printf("Not configured any virtual host. Must check config [%s]\n", configfile)
		os.Exit(1)

	}

}
