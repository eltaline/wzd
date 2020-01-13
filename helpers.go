package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/eltaline/bolt"
	"github.com/eltaline/machineid"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unsafe"
)

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

func FileCount(dirpath string) (cnt int, err error) {

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

func FileExists(filename string) bool {

	if fi, err := os.Stat(filename); err == nil {

		if fi.Mode().IsRegular() {
			return true
		}

	}

	return false

}

// Dir Exists Handler

func DirExists(filename string) bool {

	if fi, err := os.Stat(filename); err == nil {

		if fi.Mode().IsDir() {
			return true
		}

	}

	return false

}

// Files Keys Iterator Handler

func FileKeys(dirpath string) (keys []string, err error) {

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

func RemoveFile(file string, directory string, deldir bool) error {

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

func KeyExists(db *bolt.DB, bucket string, file string) (exkey bool, err error) {

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

func KeyCount(db *bolt.DB, bucket string) (cnt int, err error) {

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

func AllKeys(db *bolt.DB, bucket string, dirpath string, uniq bool) (keys []string, err error) {

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

func RemoveFileDB(file string, directory string, deldir bool) error {

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

func ContentType(filename string, filesize int64, contbuffer []byte, csizebuffer int) (conttype string, err error) {

	conttype = mime.TypeByExtension(filepath.Ext(filename))

	if conttype == "" && filesize >= 512 {

		conttype = http.DetectContentType(contbuffer[:csizebuffer])
		return conttype, err

	}

	return conttype, err

}

// Accept Ranges Helper

func ParseByRange(rngs string, size int64) ([]ReqRange, error) {

	rngerr := errors.New("bad range")

	var ranges []ReqRange

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

		var r ReqRange

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

// Check Options With Boolean/Int Functions

func Check(bvar bool, sec string, name string, val string, perm string, ferr func(string, string, string, string)) {

	if !bvar {
		ferr(sec, name, val, perm)
	}

}

func DoExit(sec string, name string, val string, perm string) {
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
