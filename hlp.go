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
	"time"
	"unsafe"
)

// BoltDB Handlers

// BoltOpenWrite : open BoltDB for write operations
func BoltOpenWrite(dbpath string, fmode os.FileMode, timeout time.Duration, opentries int, freelist string) (*bolt.DB, error) {

	i := 0

	flist := bolt.FreelistMapType

	switch {
	case freelist == "hashmap":
		flist = bolt.FreelistMapType
	case freelist == "array":
		flist = bolt.FreelistArrayType
	}

	for {

		i++

		db, err := bolt.Open(dbpath, fmode, &bolt.Options{Timeout: timeout, FreelistType: flist})
		if err == nil {
			return db, err
		}

		if i >= opentries {
			return db, err
		}

		time.Sleep(defsleep)

	}

}

// BoltOpenRead : open BoltDB for readonly operations
func BoltOpenRead(dbpath string, fmode os.FileMode, timeout time.Duration, opentries int, freelist string) (*bolt.DB, error) {

	i := 0

	flist := bolt.FreelistMapType

	switch {
	case freelist == "hashmap":
		flist = bolt.FreelistMapType
	case freelist == "array":
		flist = bolt.FreelistArrayType
	}

	for {

		i++

		db, err := bolt.Open(dbpath, fmode, &bolt.Options{Timeout: timeout, ReadOnly: true, FreelistType: flist})
		if err == nil {
			return db, err
		}

		if i >= opentries {
			return db, err
		}

		time.Sleep(defsleep)

	}

}

// System Helpers

// DetectEndian : determine system endianess function
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

// DetectUser : determine current system user and group
func DetectUser() {

	cuser, err := user.Current()
	if err != nil {
		fmt.Printf("Can`t determine current user error | %v\n", err)
		os.Exit(1)
	}

	Uid, err = strconv.ParseInt(cuser.Uid, 10, 16)
	if err != nil {
		fmt.Printf("Can`t int convert current user uid error | %v\n", err)
		os.Exit(1)
	}

	Gid, err = strconv.ParseInt(cuser.Gid, 10, 16)
	if err != nil {
		fmt.Printf("Can`t int convert current user gid error | %v\n", err)
		os.Exit(1)
	}

}

// GetPID : get current pid number and return int and string representation of pid
func GetPID() (gpid string, fpid string) {

	gpid = fmt.Sprintf("%d", os.Getpid())
	fpid = fmt.Sprintf("%s\n", gpid)

	return gpid, fpid

}

// MachineID : set globally machine identity
func MachineID() {

	var err error

	machid, err = machineid.ID()
	if err != nil {
		machid = "nomachineid"
	}

}

// File Helpers

// FileExists : check existence of requested file
func FileExists(filename string) bool {

	if fi, err := os.Stat(filename); err == nil {

		if fi.Mode().IsRegular() {
			return true
		}

	}

	return false

}

// FileOrLinkExists : check existence of requested file or symlink
func FileOrLinkExists(filename string) bool {

	if fi, err := os.Stat(filename); err == nil {

		if fi.Mode().IsRegular() {
			return true
		}

	}

	if _, err := filepath.EvalSymlinks(filename); err == nil {
		return true
	}

	return false

}

// DirExists : check existence of requested directory
func DirExists(filename string) bool {

	if fi, err := os.Stat(filename); err == nil {

		if fi.Mode().IsDir() {
			return true
		}

	}

	return false

}

// RemoveFile : remove requested file and/or empty dir
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

// DB Helpers

// KeyExists : check existence of requested key in index/size/time bucket
func KeyExists(db *bolt.DB, xbucket string, file string) (data string, err error) {

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("index/size/time bucket not exists")

		b := tx.Bucket([]byte(xbucket))
		if b != nil {

			val := b.Get([]byte(file))
			if val != nil {
				data = string(val)
			}

		} else {
			return verr
		}

		return nil

	})

	return data, err

}

// KeyCount : count keys in an index bucket for requested directory
func KeyCount(db *bolt.DB, ibucket string) (cnt int, err error) {

	cnt = 1

	var sts bolt.BucketStats

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("index bucket not exists")

		b := tx.Bucket([]byte(ibucket))
		if b != nil {
			sts = b.Stats()
			cnt = sts.KeyN
		} else {
			return verr
		}

		return nil

	})

	return cnt, err

}

// KeyCountBucket : count keys in a requested bucket
func KeyCountBucket(db *bolt.DB, bucket string) (cnt int, err error) {

	cnt = 1

	var sts bolt.BucketStats

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("bucket not exists")

		b := tx.Bucket([]byte(bucket))
		if b != nil {
			sts = b.Stats()
			cnt = sts.KeyN
		} else {
			return verr
		}

		return nil

	})

	return cnt, err

}

// BucketCount : get count of buckets from count bucket in requested directory
func BucketCount(db *bolt.DB, cbucket string) (cnt uint64, err error) {

	cnt = uint64(0)

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("count bucket not exists")

		b := tx.Bucket([]byte(cbucket))
		if b != nil {

			val := b.Get([]byte("counter"))
			if val != nil {
				cnt = Endian.Uint64(val)
			}

		} else {
			return verr
		}

		return nil

	})

	return cnt, err

}

// BucketStats : get current size of requested bucket
func BucketStats(db *bolt.DB, bucket string) (cnt int, err error) {

	cnt = 0

	var sts bolt.BucketStats

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("bucket not exists")

		b := tx.Bucket([]byte(bucket))
		if b != nil {
			sts = b.Stats()
			cnt = sts.LeafInuse
		} else {
			return verr
		}

		return nil

	})

	return cnt, err

}

// RemoveFileDB : remove requested BoltDB file and/or empty dir
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

// Names/Count Helpers

// FileKeys : get file names through requested directory
func FileKeys(dirpath string, limit int64, offset int64) (keys []string, err error) {

	var k string

	allfiles, err := ioutil.ReadDir(dirpath)
	if err != nil {
		return keys, err
	}

	cl := int64(1)
	co := int64(1)

	for _, file := range allfiles {

		bname := rgxbolt.MatchString(file.Name())
		cname := rgxcrcbolt.MatchString(file.Name())

		if !bname && !cname {

			if co < offset && offset > -1 {
				co++
				continue
			}

			if cl > limit && limit > -1 {
				break
			}

			k = file.Name()
			filename := fmt.Sprintf("%s/%s", dirpath, k)

			lnfile, err := os.Lstat(filename)
			if err != nil {
				continue
			}

			if lnfile.Mode()&os.ModeType != 0 {
				continue
			}

			keys = append(keys, k)

			co++
			cl++

		}

	}

	sort.Strings(keys)

	return keys, err

}

// FileKeysInfo : get file names with info through requested directory
func FileKeysInfo(dirpath string, limit int64, offset int64) (ikeys []KeysInfo, err error) {

	var filekeys []string
	var k string

	var ik KeysInfo

	allfiles, err := ioutil.ReadDir(dirpath)
	if err != nil {
		return ikeys, err
	}

	cl := int64(1)
	co := int64(1)

	for _, file := range allfiles {

		bname := rgxbolt.MatchString(file.Name())
		cname := rgxcrcbolt.MatchString(file.Name())

		if !bname && !cname {

			if co < offset && offset > -1 {
				co++
				continue
			}

			if cl > limit && limit > -1 {
				break
			}

			k = file.Name()
			filekeys = append(filekeys, k)

			co++
			cl++

		}

	}

	sort.Strings(filekeys)

	for v := range filekeys {

		filename := fmt.Sprintf("%s/%s", dirpath, filekeys[v])

		lnfile, err := os.Lstat(filename)
		if err != nil {
			continue
		}

		if lnfile.Mode()&os.ModeType != 0 {
			continue
		}

		infile, err := os.Stat(filename)
		if err != nil {
			continue
		}

		ik.Key = filekeys[v]
		ik.Type = 0
		ik.Size = infile.Size()
		ik.Date = int32(infile.ModTime().Unix())

		ikeys = append(ikeys, ik)

	}

	return ikeys, err

}

// DBKeys : get key names through requested directory from bolt archive
func DBKeys(db *bolt.DB, ibucket string, limit int64, offset int64) (keys []string, err error) {

	var k string

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("index bucket not exists")

		b := tx.Bucket([]byte(ibucket))
		if b != nil {

			pos := b.Cursor()

			cl := int64(1)
			co := int64(1)

			for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

				if co < offset && offset > -1 {
					co++
					continue
				}

				if cl > limit && limit > -1 {
					break
				}

				k = fmt.Sprintf("%s", inkey)
				keys = append(keys, k)

				co++
				cl++

			}

		} else {
			return verr
		}

		return nil

	})
	if err != nil {
		return keys, err
	}

	sort.Strings(keys)

	return keys, err

}

// DBKeysInfo : get key names with info through requested directory from bolt archive
func DBKeysInfo(db *bolt.DB, ibucket string, limit int64, offset int64) (ikeys []KeysInfo, err error) {

	var dbkeys []string
	var k string

	var ik KeysInfo

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("index bucket not exists")

		b := tx.Bucket([]byte(ibucket))
		if b != nil {

			pos := b.Cursor()

			cl := int64(1)
			co := int64(1)

			for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

				if co < offset && offset > -1 {
					co++
					continue
				}

				if cl > limit && limit > -1 {
					break
				}

				k = fmt.Sprintf("%s", inkey)
				dbkeys = append(dbkeys, k)

				co++
				cl++

			}

		} else {
			return verr
		}

		return nil

	})
	if err != nil {
		return ikeys, err
	}

	sort.Strings(dbkeys)

	for v := range dbkeys {

		ik.Key = dbkeys[v]
		ik.Type = 1

		err = db.View(func(tx *bolt.Tx) error {

			verr := errors.New("size bucket not exists")

			b := tx.Bucket([]byte("size"))
			if b != nil {

				val := b.Get([]byte(dbkeys[v]))
				if val != nil {
					ik.Size = int64(Endian.Uint64(val))
				}

			} else {
				return verr
			}

			return nil

		})
		if err != nil {
			return ikeys, err
		}

		err = db.View(func(tx *bolt.Tx) error {

			verr := errors.New("time bucket not exists")

			b := tx.Bucket([]byte("time"))
			if b != nil {

				val := b.Get([]byte(dbkeys[v]))
				if val != nil {
					ik.Date = int32(Endian.Uint32(val))
				}

			} else {
				return verr
			}

			return nil

		})
		if err != nil {
			return ikeys, err
		}

		ikeys = append(ikeys, ik)

	}

	return ikeys, err

}

// AllKeys : get summary file and key names through requested directory and from bolt archive
func AllKeys(db *bolt.DB, ibucket string, dirpath string, uniq bool, limit int64, offset int64) (keys []string, err error) {

	var allkeys []string
	compare := map[string]bool{}
	var k string

	cl := int64(1)
	co := int64(1)

	allfiles, err := ioutil.ReadDir(dirpath)
	if err != nil {
		return keys, err
	}

	for _, file := range allfiles {

		bname := rgxbolt.MatchString(file.Name())
		cname := rgxcrcbolt.MatchString(file.Name())

		if !bname && !cname {

			if co < offset && offset > -1 {
				co++
				continue
			}

			if cl > limit && limit > -1 {
				break
			}

			k = file.Name()
			filename := fmt.Sprintf("%s/%s", dirpath, k)

			lnfile, err := os.Lstat(filename)
			if err != nil {
				continue
			}

			if lnfile.Mode()&os.ModeType != 0 {
				continue
			}

			allkeys = append(allkeys, k)

			co++
			cl++

		}

	}

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("index bucket not exists")

		b := tx.Bucket([]byte(ibucket))
		if b != nil {

			pos := b.Cursor()

			for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

				if co < offset && offset > -1 {
					co++
					continue
				}

				if cl > limit && limit > -1 {
					break
				}

				k = fmt.Sprintf("%s", inkey)
				allkeys = append(allkeys, k)

				co++
				cl++

			}

		} else {
			return verr
		}

		return nil

	})

	if err != nil {
		return keys, err
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

// AllKeysInfo : get summary file and key names with info through requested directory and from bolt archive
func AllKeysInfo(db *bolt.DB, ibucket string, dirpath string, uniq bool, limit int64, offset int64) (ikeys []KeysInfo, err error) {

	var filekeys []string
	var dbkeys []string
	compare := map[string]bool{}
	var k string

	var ik KeysInfo

	cl := int64(1)
	co := int64(1)

	allfiles, err := ioutil.ReadDir(dirpath)
	if err != nil {
		return ikeys, err
	}

	for _, file := range allfiles {

		bname := rgxbolt.MatchString(file.Name())
		cname := rgxcrcbolt.MatchString(file.Name())

		if !bname && !cname {

			if co < offset && offset > -1 {
				co++
				continue
			}

			if cl > limit && limit > -1 {
				break
			}

			k = file.Name()
			filekeys = append(filekeys, k)
			compare[k] = true

			co++
			cl++

		}

	}

	sort.Strings(filekeys)

	for v := range filekeys {

		filename := fmt.Sprintf("%s/%s", dirpath, filekeys[v])

		lnfile, err := os.Lstat(filename)
		if err != nil {
			continue
		}

		if lnfile.Mode()&os.ModeType != 0 {
			continue
		}

		infile, err := os.Stat(filename)
		if err != nil {
			continue
		}

		ik.Key = filekeys[v]
		ik.Type = 0
		ik.Size = infile.Size()
		ik.Date = int32(infile.ModTime().Unix())

		ikeys = append(ikeys, ik)

	}

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("index bucket not exists")

		b := tx.Bucket([]byte(ibucket))
		if b != nil {

			pos := b.Cursor()

			for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

				if co < offset && offset > -1 {
					co++
					continue
				}

				if cl > limit && limit > -1 {
					break
				}

				k = fmt.Sprintf("%s", inkey)
				dbkeys = append(dbkeys, k)

				co++
				cl++

			}

		} else {
			return verr
		}

		return nil

	})
	if err != nil {
		return ikeys, err
	}

	sort.Strings(dbkeys)

	if uniq {

		for v := range dbkeys {

			if !compare[dbkeys[v]] {

				ik.Key = dbkeys[v]
				ik.Type = 1

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("size bucket not exists")

					b := tx.Bucket([]byte("size"))
					if b != nil {

						val := b.Get([]byte(dbkeys[v]))
						if val != nil {
							ik.Size = int64(Endian.Uint64(val))
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("time bucket not exists")

					b := tx.Bucket([]byte("time"))
					if b != nil {

						val := b.Get([]byte(dbkeys[v]))
						if val != nil {
							ik.Date = int32(Endian.Uint32(val))
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					return ikeys, err
				}

				ikeys = append(ikeys, ik)

			}

		}

	} else {

		for v := range dbkeys {

			ik.Key = dbkeys[v]
			ik.Type = 1

			err = db.View(func(tx *bolt.Tx) error {

				verr := errors.New("size bucket not exists")

				b := tx.Bucket([]byte("size"))
				if b != nil {

					val := b.Get([]byte(dbkeys[v]))
					if val != nil {
						ik.Size = int64(Endian.Uint64(val))
					}

				} else {
					return verr
				}

				return nil

			})
			if err != nil {
				return ikeys, err
			}

			err = db.View(func(tx *bolt.Tx) error {

				verr := errors.New("time bucket not exists")

				b := tx.Bucket([]byte("time"))
				if b != nil {

					val := b.Get([]byte(dbkeys[v]))
					if val != nil {
						ik.Date = int32(Endian.Uint32(val))
					}

				} else {
					return verr
				}

				return nil

			})
			if err != nil {
				return ikeys, err
			}

			ikeys = append(ikeys, ik)

		}

	}

	return ikeys, err

}

// FileCount : count files in a requested directory without .bolt and .crcbolt files
func FileCount(dirpath string) (cnt int, err error) {

	cnt = 0

	allfiles, err := ioutil.ReadDir(dirpath)
	if err != nil {
		return 0, err
	}

	for _, file := range allfiles {

		bname := rgxbolt.MatchString(file.Name())
		cname := rgxcrcbolt.MatchString(file.Name())

		if !file.IsDir() && !bname && !cname {
			cnt++
		}
	}

	return cnt, err

}

// Working helpers

// ContentType : get a content type of requested file/value
func ContentType(filename string, filesize int64, contbuffer []byte, csizebuffer int) (conttype string, err error) {

	conttype = mime.TypeByExtension(filepath.Ext(filename))

	if conttype == "" && filesize >= 512 {

		conttype = http.DetectContentType(contbuffer[:csizebuffer])
		return conttype, err

	}

	return conttype, err

}

// ParseByRange : Accept-Ranges helper
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

// StringOne : function returns true and sequence of received value if value == 1
func StringOne(values ...interface{}) (bool, int) {

	c := 0

	for _, value := range values {
		c++

		if value == "1" {
			return true, c
		}

	}

	return false, 0

}

// Check Options With Boolean/Int Functions

// Check : if received value is false, then run DoExit function
func Check(bvar bool, sec string, name string, val string, perm string, ferr func(string, string, string, string)) {

	if !bvar {
		ferr(sec, name, val, perm)
	}

}

// DoExit : exit program function
func DoExit(sec string, name string, val string, perm string) {
	fmt.Printf("Bad option value error | Section [%s] | Name [%s] | Value [%v] | Permissible Value [%s]\n", sec, name, val, perm)
	os.Exit(1)
}

// RBInt : check int32 acceptable range function and then return true or false
func RBInt(i int, min int, max int) bool {

	switch {
	case i >= min && i <= max:
		return true
	default:
		return false
	}

}

// RBInt64 : check int64 acceptable range function and return true or false
func RBInt64(i int64, min int64, max int64) bool {

	switch {
	case i >= min && i <= max:
		return true
	default:
		return false
	}

}
