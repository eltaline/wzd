package main

import (
	"context"
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
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
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
	CMPSCHED          bool
	CMPDIR            string
	CMPTIME           int
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

type ReqRange struct {
	start  int64
	length int64
}

type Compact struct {
	Path   string
	MachID string
	Time   time.Time
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

	defsleep time.Duration = 1 * time.Second

	cmpdir = "/var/lib/wzd/"

	cmpsched bool = true

	cmptime  int           = 30
	cmpcheck time.Duration = 5 * time.Second

	rgxbolt  = regexp.MustCompile(`(\.bolt$)`)
	rgxctype = regexp.MustCompile("(multipart)")
)

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
	Check(mchreadtimeout, "[global]", "readtimeout", fmt.Sprintf("%d", config.Global.READTIMEOUT), "from 0 to 86400", DoExit)

	mchreadheadertimeout := RBInt(config.Global.READHEADERTIMEOUT, 0, 86400)
	Check(mchreadheadertimeout, "[global]", "readheadertimeout", fmt.Sprintf("%d", config.Global.READHEADERTIMEOUT), "from 0 to 86400", DoExit)

	mchidletimeout := RBInt(config.Global.IDLETIMEOUT, 0, 86400)
	Check(mchidletimeout, "[global]", "idletimeout", fmt.Sprintf("%d", config.Global.IDLETIMEOUT), "from 0 to 86400", DoExit)

	mchwritetimeout := RBInt(config.Global.WRITETIMEOUT, 0, 86400)
	Check(mchwritetimeout, "[global]", "writetimeout", fmt.Sprintf("%d", config.Global.WRITETIMEOUT), "from 0 to 86400", DoExit)

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
	Check(mchdebugmode, "[global]", "debugmode", (fmt.Sprintf("%t", config.Global.DEBUGMODE)), "true or false", DoExit)

	if config.Global.PIDFILE != "" {
		rgxpidfile := regexp.MustCompile("^(/[^/\x00]*)+/?$")
		mchpidfile := rgxpidfile.MatchString(config.Global.PIDFILE)
		Check(mchpidfile, "[global]", "pidfile", config.Global.PIDFILE, "ex. /run/wzd/wzd.pid", DoExit)
	} else {
		config.Global.PIDFILE = "/run/wzd/wzd.pid"
	}

	if config.Global.LOGDIR != "" {
		rgxlogdir := regexp.MustCompile("^(/[^/\x00]*)+/?$")
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
		rgxcmpdir := regexp.MustCompile("^(/[^/\x00]*)+/?$")
		mchcmpdir := rgxcmpdir.MatchString(config.Global.CMPDIR)
		Check(mchcmpdir, "[global]", "cmpdir", config.Global.CMPDIR, "ex. /var/lib/wzd", DoExit)
	} else {
		config.Global.CMPDIR = "/var/lib/wzd"
	}

	rgxcmpsched := regexp.MustCompile("^(?i)(true|false)$")
	mchcmpsched := rgxcmpsched.MatchString(fmt.Sprintf("%t", config.Global.CMPSCHED))
	Check(mchcmpsched, "[global]", "cmpsched", (fmt.Sprintf("%t", config.Global.CMPSCHED)), "true or false", DoExit)

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
	case config.Global.CMPSCHED:
		appLogger.Warnf("| Compaction Scheduler [ENABLED]")
		appLogger.Warnf("| Compaction Time > [%d] days", config.Global.CMPTIME)
		appLogger.Warnf("| Compaction Scheduler Check Every [%d] seconds", config.Global.CMPCHECK)
	default:
		appLogger.Warnf("| Compaction Scheduler [DISABLED]")
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
		Check(mchroot, section, "root", Server.ROOT, "ex. /var/storage/localhost", DoExit)

		mchupload := rgxupload.MatchString(fmt.Sprintf("%t", Server.UPLOAD))
		Check(mchupload, section, "upload", (fmt.Sprintf("%t", Server.UPLOAD)), "true or false", DoExit)

		mchdelete := rgxdelete.MatchString(fmt.Sprintf("%t", Server.DELETE))
		Check(mchdelete, section, "delete", (fmt.Sprintf("%t", Server.DELETE)), "true or false", DoExit)

		mchcompaction := rgxcompaction.MatchString(fmt.Sprintf("%t", Server.COMPACTION))
		Check(mchcompaction, section, "compaction", (fmt.Sprintf("%t", Server.COMPACTION)), "true or false", DoExit)

		mchgetbolt := rgxgetbolt.MatchString(fmt.Sprintf("%t", Server.GETBOLT))
		Check(mchgetbolt, section, "getbolt", (fmt.Sprintf("%t", Server.GETBOLT)), "true or false", DoExit)

		mchgetcount := rgxgetcount.MatchString(fmt.Sprintf("%t", Server.GETCOUNT))
		Check(mchgetcount, section, "getcount", (fmt.Sprintf("%t", Server.GETCOUNT)), "true or false", DoExit)

		mchgetkeys := rgxgetkeys.MatchString(fmt.Sprintf("%t", Server.GETKEYS))
		Check(mchgetkeys, section, "getkeys", (fmt.Sprintf("%t", Server.GETKEYS)), "true or false", DoExit)

		mchnonunique := rgxnonunique.MatchString(fmt.Sprintf("%t", Server.NONUNIQUE))
		Check(mchnonunique, section, "nonunique", (fmt.Sprintf("%t", Server.NONUNIQUE)), "true or false", DoExit)

		mchwriteintegrity := rgxwriteintegrity.MatchString(fmt.Sprintf("%t", Server.WRITEINTEGRITY))
		Check(mchwriteintegrity, section, "writeintegrity", (fmt.Sprintf("%t", Server.WRITEINTEGRITY)), "true or false", DoExit)

		mchreadintegrity := rgxreadintegrity.MatchString(fmt.Sprintf("%t", Server.READINTEGRITY))
		Check(mchreadintegrity, section, "readintegrity", (fmt.Sprintf("%t", Server.READINTEGRITY)), "true or false", DoExit)

		mchtrytimes := RBInt(Server.TRYTIMES, 1, 1000)
		Check(mchtrytimes, section, "trytimes", (fmt.Sprintf("%d", Server.TRYTIMES)), "from 1 to 1000", DoExit)

		mchlocktimeout := RBInt(Server.LOCKTIMEOUT, 1, 3600)
		Check(mchlocktimeout, section, "locktimeout", (fmt.Sprintf("%d", Server.LOCKTIMEOUT)), "from 1 to 3600", DoExit)

		mchfmaxsize := RBInt64(Server.FMAXSIZE, 1, 536870912)
		Check(mchfmaxsize, section, "fmaxsize", (fmt.Sprintf("%d", Server.FMAXSIZE)), "from 1 to 536870912", DoExit)

		mchargs := rgxargs.MatchString(fmt.Sprintf("%t", Server.ARGS))
		Check(mchargs, section, "args", (fmt.Sprintf("%t", Server.ARGS)), "true or false", DoExit)

		mchcctrl := RBInt(Server.CCTRL, 0, 2147483647)
		Check(mchcctrl, section, "cctrl", (fmt.Sprintf("%d", Server.CCTRL)), "from 0 to 2147483647", DoExit)

		mchminbuffer := RBInt64(Server.MINBUFFER, 4096, 524288)
		Check(mchminbuffer, section, "minbuffer", (fmt.Sprintf("%d", Server.MINBUFFER)), "from 4096 to 524288", DoExit)

		mchlowbuffer := RBInt64(Server.LOWBUFFER, 1048576, 33554432)
		Check(mchlowbuffer, section, "lowbuffer", (fmt.Sprintf("%d", Server.LOWBUFFER)), "from 1048576 to 33554432", DoExit)

		mchmedbuffer := RBInt64(Server.MEDBUFFER, 67108864, 268169216)
		Check(mchmedbuffer, section, "medbuffer", (fmt.Sprintf("%d", Server.MEDBUFFER)), "from 67108864 to 268169216", DoExit)

		mchbigbuffer := RBInt64(Server.BIGBUFFER, 536870912, 2147483647)
		Check(mchbigbuffer, section, "bigbuffer", (fmt.Sprintf("%d", Server.BIGBUFFER)), "from 536870912 to 2147483647", DoExit)

		mchfilemode := rgxfilemode.MatchString(fmt.Sprintf("%d", Server.FILEMODE))
		Check(mchfilemode, section, "filemode", (fmt.Sprintf("%d", Server.FILEMODE)), "from 0600 to 0666", DoExit)

		mchdirmode := rgxdirmode.MatchString(fmt.Sprintf("%d", Server.DIRMODE))
		Check(mchdirmode, section, "dirmode", (fmt.Sprintf("%d", Server.DIRMODE)), "from 0700 to 0777", DoExit)

		mchdelbolt := rgxdelbolt.MatchString(fmt.Sprintf("%t", Server.DELBOLT))
		Check(mchdelbolt, section, "delbolt", (fmt.Sprintf("%t", Server.DELBOLT)), "true or false", DoExit)

		mchdeldir := rgxdeldir.MatchString(fmt.Sprintf("%t", Server.DELDIR))
		Check(mchdeldir, section, "deldir", (fmt.Sprintf("%t", Server.DELDIR)), "true or false", DoExit)

		// Output Important Server Configuration Options

		appLogger.Warnf("| Host [%s] | Max File Size [%d]", Server.HOST, Server.FMAXSIZE)

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
		case Server.GETCOUNT:
			appLogger.Warnf("| Host [%s] | Get Count Keys/Files [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Get Count Keys/Files [DISABLED]", Server.HOST)
		}

		switch {
		case Server.GETKEYS:
			appLogger.Warnf("| Host [%s] | Get Names Keys/Files [ENABLED]", Server.HOST)
		default:
			appLogger.Warnf("| Host [%s] | Get Names Keys/Files [DISABLED]", Server.HOST)
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

	// Default Timers / Tries

	defsleep = time.Duration(config.Global.DEFSLEEP) * time.Second

	// Compaction Configuration

	cmpdir = config.Global.CMPDIR

	cmptime = config.Global.CMPTIME
	cmpcheck = time.Duration(config.Global.CMPCHECK) * time.Second

	// Pid Handling

	appLogger.Warnf("wZD server running with pid: %s", gpid)

	// Map Mutex

	keymutex := mmutex.NewMMutex()

	// Open Compaction DB

	options := badgerhold.DefaultOptions
	options.Dir = cmpdir
	options.ValueDir = cmpdir

	cdb, err := badgerhold.Open(options)
	if err != nil {
		appLogger.Errorf("| Can`t open/create compaction db | DB Directory [%s] | %v", cmpdir, err)
		os.Exit(1)
	}
	defer cdb.Close()

	// Go Compaction Scheduler

	cmpsched = config.Global.CMPSCHED

	if cmpsched {
		go CompactScheduler(cdb)
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

	app.Get("/{directory:path}", ZDGet())
	app.Head("/{directory:path}", ZDGet())
	app.Options("/{directory:path}", ZDGet())
	app.Put("/{directory:path}", ZDPut(keymutex, cdb))
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
