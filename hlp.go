package main

import (
	"encoding/binary"
	"encoding/hex"
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
	"regexp"
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

// KeysCount : count keys in an index bucket for requested directory
func KeysCount(db *bolt.DB, ibucket string) (cnt int, err error) {

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

// KeysCountBucket : count keys in a requested bucket
func KeysCountBucket(db *bolt.DB, bucket string) (cnt int, err error) {

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

// FileKeys : search file names through requested directory
func FileKeys(dirpath string, limit uint64, offset uint64, expression string, recursive uint8, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string) (ikeys []Keys, err error) {

	var filekeys []string
	var k string

	var ik Keys

	var sdcheck bool = false

	iminsize := int64(minsize)
	imaxsize := int64(maxsize)
	iminstmp := int64(minstmp)
	imaxstmp := int64(maxstmp)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	rgxexpression, err := regexp.Compile(expression)
	if err != nil {
		return ikeys, err
	}

	dirpath = filepath.Clean(dirpath)
	url = strings.TrimSuffix(url, "/")

	paths, err := RecursiveDirSearch(dirpath, recursive)
	if err != nil {
		return ikeys, err
	}

	cl := uint64(1)
	co := uint64(1)

	for _, dirname := range paths {

		files, err := ioutil.ReadDir(dirname)
		if err != nil {
			return ikeys, err
		}

		for _, file := range files {

			k = file.Name()

			bname := rgxbolt.MatchString(k)
			cname := rgxcrcbolt.MatchString(k)

			if !file.IsDir() && !bname && !cname {

				if !rgxexpression.MatchString(k) {
					continue
				}

				if co < offset && offset > 0 {
					co++
					continue
				}

				if cl > limit && limit > 0 {
					break
				}

				filename := dirname + "/" + k

				lnfile, err := os.Lstat(filename)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				filekeys = append(filekeys, filename)

				if stopfirst == 1 {
					stopfirst = 255
					break
				}

				co++
				cl++

			}

		}

		if stopfirst == 255 {
			break
		}

		if cl > limit && limit > 0 {
			break
		}

	}

	sort.Strings(filekeys)

	for _, filename := range filekeys {

		if sdcheck {

			infile, err := os.Stat(filename)
			if err != nil {
				continue
			}

			fsize := infile.Size()
			fdate := infile.ModTime().Unix()

			switch {
			case fsize < iminsize && minsize > 0:
				continue
			case fsize > imaxsize && maxsize > 0:
				continue
			case fdate < iminstmp && minstmp > 0:
				continue
			case fdate > imaxstmp && maxstmp > 0:
				continue
			}

		}

		filename = strings.TrimPrefix(filename, dirpath+"/")

		if withurl {
			filename = url + "/" + filename
		}

		ik.Key = filename

		ikeys = append(ikeys, ik)

	}

	return ikeys, err

}

// FileKeysInfo : search file names with info through requested directory
func FileKeysInfo(dirpath string, limit uint64, offset uint64, expression string, recursive uint8, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string) (ikeys []KeysInfo, err error) {

	var filekeys []string
	var k string

	var ik KeysInfo

	var sdcheck bool = false

	iminsize := int64(minsize)
	imaxsize := int64(maxsize)
	iminstmp := int64(minstmp)
	imaxstmp := int64(maxstmp)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	rgxexpression, err := regexp.Compile(expression)
	if err != nil {
		return ikeys, err
	}

	dirpath = filepath.Clean(dirpath)
	url = strings.TrimSuffix(url, "/")

	paths, err := RecursiveDirSearch(dirpath, recursive)
	if err != nil {
		return ikeys, err
	}

	cl := uint64(1)
	co := uint64(1)

	for _, dirname := range paths {

		files, err := ioutil.ReadDir(dirname)
		if err != nil {
			return ikeys, err
		}

		for _, file := range files {

			k = file.Name()

			bname := rgxbolt.MatchString(k)
			cname := rgxcrcbolt.MatchString(k)

			if !file.IsDir() && !bname && !cname {

				if !rgxexpression.MatchString(k) {
					continue
				}

				if co < offset && offset > 0 {
					co++
					continue
				}

				if cl > limit && limit > 0 {
					break
				}

				filename := dirname + "/" + k

				lnfile, err := os.Lstat(filename)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				filekeys = append(filekeys, filename)

				if stopfirst == 1 {
					stopfirst = 255
					break
				}

				co++
				cl++

			}

		}

		if stopfirst == 255 {
			break
		}

		if cl > limit && limit > 0 {
			break
		}

	}

	sort.Strings(filekeys)

	for _, filename := range filekeys {

		infile, err := os.Stat(filename)
		if err != nil {
			continue
		}

		fsize := infile.Size()
		fdate := infile.ModTime().Unix()

		if sdcheck {

			switch {
			case fsize < iminsize && minsize > 0:
				continue
			case fsize > imaxsize && maxsize > 0:
				continue
			case fdate < iminstmp && minstmp > 0:
				continue
			case fdate > imaxstmp && maxstmp > 0:
				continue
			}

		}

		filename = strings.TrimPrefix(filename, dirpath+"/")

		if withurl {
			filename = url + "/" + filename
		}

		ik.Key = filename
		ik.Type = 0
		ik.Size = uint64(fsize)
		ik.Date = uint64(fdate)

		ikeys = append(ikeys, ik)

	}

	return ikeys, err

}

// FileKeysSearch : search file names/names with values through requested directory
func FileKeysSearch(dirpath string, limit uint64, offset uint64, expression string, recursive uint8, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withvalue bool, vmaxsize int64) (ikeys []KeysSearch, err error) {

	var filekeys []string
	var k string

	var ik KeysSearch

	var sdcheck bool = false

	iminsize := int64(minsize)
	imaxsize := int64(maxsize)
	iminstmp := int64(minstmp)
	imaxstmp := int64(maxstmp)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	rgxexpression, err := regexp.Compile(expression)
	if err != nil {
		return ikeys, err
	}

	dirpath = filepath.Clean(dirpath)
	url = strings.TrimSuffix(url, "/")

	paths, err := RecursiveDirSearch(dirpath, recursive)
	if err != nil {
		return ikeys, err
	}

	cl := uint64(1)
	co := uint64(1)

	for _, dirname := range paths {

		files, err := ioutil.ReadDir(dirname)
		if err != nil {
			return ikeys, err
		}

		for _, file := range files {

			k = file.Name()

			bname := rgxbolt.MatchString(k)
			cname := rgxcrcbolt.MatchString(k)

			if !file.IsDir() && !bname && !cname {

				if !rgxexpression.MatchString(k) {
					continue
				}

				if co < offset && offset > 0 {
					co++
					continue
				}

				if cl > limit && limit > 0 {
					break
				}

				filename := dirname + "/" + k

				lnfile, err := os.Lstat(filename)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				filekeys = append(filekeys, filename)

				if stopfirst == 1 {
					stopfirst = 255
					break
				}

				co++
				cl++

			}

		}

		if stopfirst == 255 {
			break
		}

		if cl > limit && limit > 0 {
			break
		}

	}

	sort.Strings(filekeys)

	for _, filename := range filekeys {

		var value []byte

		infile, err := os.Stat(filename)
		if err != nil {
			continue
		}

		fsize := infile.Size()
		fdate := infile.ModTime().Unix()

		if sdcheck {

			switch {
			case fsize < iminsize && minsize > 0:
				continue
			case fsize > imaxsize && maxsize > 0:
				continue
			case fdate < iminstmp && minstmp > 0:
				continue
			case fdate > imaxstmp && maxstmp > 0:
				continue
			}

		}

		if withvalue && fsize <= vmaxsize {

			value, err = ioutil.ReadFile(filename)
			if err != nil {
				return ikeys, err
			}

		}

		filename = strings.TrimPrefix(filename, dirpath+"/")

		if withurl {
			filename = url + "/" + filename
		}

		ik.Key = filename
		ik.Type = 0
		ik.Size = uint64(fsize)
		ik.Date = uint64(fdate)

		vhex := make([]byte, hex.EncodedLen(len(value)))
		hex.Encode(vhex, value)

		ik.Value = vhex

		ikeys = append(ikeys, ik)

	}

	return ikeys, err

}

// DBKeys : search key names through requested directory
func DBKeys(ibucket string, sbucket string, tbucket string, filemode os.FileMode, timeout time.Duration, opentries int, freelist string, dirpath string, limit uint64, offset uint64, expression string, recursive uint8, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string) (ikeys []Keys, err error) {

	var dbkeys []string
	var k string

	var ik Keys

	var sdcheck bool = false

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	rgxexpression, err := regexp.Compile(expression)
	if err != nil {
		return ikeys, err
	}

	dirpath = filepath.Clean(dirpath)
	url = strings.TrimSuffix(url, "/")

	paths, err := RecursiveDirSearch(dirpath, recursive)
	if err != nil {
		return ikeys, err
	}

	cl := uint64(1)
	co := uint64(1)

	for _, dirname := range paths {

		files, err := ioutil.ReadDir(dirname)
		if err != nil {
			return ikeys, err
		}

		for _, file := range files {

			k = file.Name()

			bname := rgxbolt.MatchString(k)

			if !file.IsDir() && bname {

				dbname := dirname + "/" + k

				lnfile, err := os.Lstat(dbname)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("index bucket not exists")

					b := tx.Bucket([]byte(ibucket))
					if b != nil {

						pos := b.Cursor()

						for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

							bk := string(inkey)

							if !rgxexpression.MatchString(bk) {
								continue
							}

							if co < offset && offset > 0 {
								co++
								continue
							}

							if cl > limit && limit > 0 {
								break
							}

							filename := dirname + "/" + bk
							dbkeys = append(dbkeys, filename)

							if stopfirst == 1 {
								stopfirst = 255
								break
							}

							co++
							cl++

						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				db.Close()

			}

			if stopfirst == 255 {
				break
			}

			if cl > limit && limit > 0 {
				break
			}

		}

		if stopfirst == 255 {
			break
		}

		if cl > limit && limit > 0 {
			break
		}

	}

	sort.Strings(dbkeys)

	for _, filename := range dbkeys {

		if sdcheck {

			var ksize uint64
			var kdate uint64

			keyname := filepath.Base(filename)
			lastpath := filepath.Dir(filename)
			boltname := filepath.Base(lastpath) + ".bolt"
			dbname := lastpath + "/" + boltname

			db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
			if err != nil {
				return ikeys, err
			}

			err = db.View(func(tx *bolt.Tx) error {

				verr := errors.New("size bucket not exists")

				b := tx.Bucket([]byte(sbucket))
				if b != nil {

					val := b.Get([]byte(keyname))
					if val != nil {
						ksize = Endian.Uint64(val)
					}

				} else {
					return verr
				}

				return nil

			})
			if err != nil {
				db.Close()
				return ikeys, err
			}

			if sdcheck {

				switch {
				case ksize < minsize && minsize > 0:
					db.Close()
					continue
				case ksize > maxsize && maxsize > 0:
					db.Close()
					continue
				}

			}

			err = db.View(func(tx *bolt.Tx) error {

				verr := errors.New("time bucket not exists")

				b := tx.Bucket([]byte(tbucket))
				if b != nil {

					val := b.Get([]byte(keyname))
					if val != nil {
						kdate = Endian.Uint64(val)
					}

				} else {
					return verr
				}

				return nil

			})
			if err != nil {
				db.Close()
				return ikeys, err
			}

			if sdcheck {

				switch {
				case kdate < minstmp && minstmp > 0:
					db.Close()
					continue
				case kdate > maxstmp && maxstmp > 0:
					db.Close()
					continue
				}

			}

			db.Close()

		}

		filename = strings.TrimPrefix(filename, dirpath+"/")

		if withurl {
			filename = url + "/" + filename
		}

		ik.Key = filename

		ikeys = append(ikeys, ik)

	}

	return ikeys, err

}

// DBKeysInfo : search key names with info through requested directory
func DBKeysInfo(ibucket string, sbucket string, tbucket string, filemode os.FileMode, timeout time.Duration, opentries int, freelist string, dirpath string, limit uint64, offset uint64, expression string, recursive uint8, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string) (ikeys []KeysInfo, err error) {

	var dbkeys []string
	var k string

	var ik KeysInfo

	var sdcheck bool = false

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	rgxexpression, err := regexp.Compile(expression)
	if err != nil {
		return ikeys, err
	}

	dirpath = filepath.Clean(dirpath)
	url = strings.TrimSuffix(url, "/")

	paths, err := RecursiveDirSearch(dirpath, recursive)
	if err != nil {
		return ikeys, err
	}

	cl := uint64(1)
	co := uint64(1)

	for _, dirname := range paths {

		files, err := ioutil.ReadDir(dirname)
		if err != nil {
			return ikeys, err
		}

		for _, file := range files {

			k = file.Name()

			bname := rgxbolt.MatchString(k)

			if !file.IsDir() && bname {

				dbname := dirname + "/" + k

				lnfile, err := os.Lstat(dbname)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("index bucket not exists")

					b := tx.Bucket([]byte(ibucket))
					if b != nil {

						pos := b.Cursor()

						for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

							bk := string(inkey)

							if !rgxexpression.MatchString(bk) {
								continue
							}

							if co < offset && offset > 0 {
								co++
								continue
							}

							if cl > limit && limit > 0 {
								break
							}

							filename := dirname + "/" + bk
							dbkeys = append(dbkeys, filename)

							if stopfirst == 1 {
								stopfirst = 255
								break
							}

							co++
							cl++

						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				db.Close()

			}

			if stopfirst == 255 {
				break
			}

			if cl > limit && limit > 0 {
				break
			}

		}

		if stopfirst == 255 {
			break
		}

		if cl > limit && limit > 0 {
			break
		}

	}

	sort.Strings(dbkeys)

	for _, filename := range dbkeys {

		keyname := filepath.Base(filename)
		lastpath := filepath.Dir(filename)
		boltname := filepath.Base(lastpath) + ".bolt"
		dbname := lastpath + "/" + boltname

		filename = strings.TrimPrefix(filename, dirpath+"/")

		if withurl {
			filename = url + "/" + filename
		}

		ik.Key = filename
		ik.Type = 1

		db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
		if err != nil {
			return ikeys, err
		}

		err = db.View(func(tx *bolt.Tx) error {

			verr := errors.New("size bucket not exists")

			b := tx.Bucket([]byte(sbucket))
			if b != nil {

				val := b.Get([]byte(keyname))
				if val != nil {
					ik.Size = Endian.Uint64(val)
				}

			} else {
				return verr
			}

			return nil

		})
		if err != nil {
			db.Close()
			return ikeys, err
		}

		if sdcheck {

			switch {
			case ik.Size < minsize && minsize > 0:
				db.Close()
				continue
			case ik.Size > maxsize && maxsize > 0:
				db.Close()
				continue
			}

		}

		err = db.View(func(tx *bolt.Tx) error {

			verr := errors.New("time bucket not exists")

			b := tx.Bucket([]byte(tbucket))
			if b != nil {

				val := b.Get([]byte(keyname))
				if val != nil {
					ik.Date = Endian.Uint64(val)
				}

			} else {
				return verr
			}

			return nil

		})
		if err != nil {
			db.Close()
			return ikeys, err
		}

		if sdcheck {

			switch {
			case ik.Date < minstmp && minstmp > 0:
				db.Close()
				continue
			case ik.Date > maxstmp && maxstmp > 0:
				db.Close()
				continue
			}

		}

		db.Close()

		ikeys = append(ikeys, ik)

	}

	return ikeys, err

}

// DBKeysSearch : search key names/names with values through requested directory
func DBKeysSearch(ibucket string, sbucket string, tbucket string, filemode os.FileMode, timeout time.Duration, opentries int, freelist string, dirpath string, limit uint64, offset uint64, expression string, recursive uint8, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withvalue bool, vmaxsize int64) (ikeys []KeysSearch, err error) {

	var dbkeys []string
	var k string

	var ik KeysSearch

	var sdcheck bool = false

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	rgxexpression, err := regexp.Compile(expression)
	if err != nil {
		return ikeys, err
	}

	dirpath = filepath.Clean(dirpath)
	url = strings.TrimSuffix(url, "/")

	paths, err := RecursiveDirSearch(dirpath, recursive)
	if err != nil {
		return ikeys, err
	}

	cl := uint64(1)
	co := uint64(1)

	for _, dirname := range paths {

		files, err := ioutil.ReadDir(dirname)
		if err != nil {
			return ikeys, err
		}

		for _, file := range files {

			k = file.Name()

			bname := rgxbolt.MatchString(k)

			if !file.IsDir() && bname {

				dbname := dirname + "/" + k

				lnfile, err := os.Lstat(dbname)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("index bucket not exists")

					b := tx.Bucket([]byte(ibucket))
					if b != nil {

						pos := b.Cursor()

						for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

							bk := string(inkey)

							if !rgxexpression.MatchString(bk) {
								continue
							}

							if co < offset && offset > 0 {
								co++
								continue
							}

							if cl > limit && limit > 0 {
								break
							}

							filename := dirname + "/" + bk
							dbkeys = append(dbkeys, filename)

							if stopfirst == 1 {
								stopfirst = 255
								break
							}

							co++
							cl++

						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				db.Close()

			}

			if stopfirst == 255 {
				break
			}

			if cl > limit && limit > 0 {
				break
			}

		}

		if stopfirst == 255 {
			break
		}

		if cl > limit && limit > 0 {
			break
		}

	}

	sort.Strings(dbkeys)

	for _, filename := range dbkeys {

		var value []byte = nil
		var bval string = ""

		keyname := filepath.Base(filename)
		lastpath := filepath.Dir(filename)
		boltname := filepath.Base(lastpath) + ".bolt"
		dbname := lastpath + "/" + boltname

		filename = strings.TrimPrefix(filename, dirpath+"/")

		if withurl {
			filename = url + "/" + filename
		}

		ik.Key = filename
		ik.Type = 1

		db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
		if err != nil {
			return ikeys, err
		}

		err = db.View(func(tx *bolt.Tx) error {

			verr := errors.New("size bucket not exists")

			b := tx.Bucket([]byte(sbucket))
			if b != nil {

				val := b.Get([]byte(keyname))
				if val != nil {
					ik.Size = Endian.Uint64(val)
				}

			} else {
				return verr
			}

			return nil

		})
		if err != nil {
			db.Close()
			return ikeys, err
		}

		if sdcheck {

			switch {
			case ik.Size < minsize && minsize > 0:
				db.Close()
				continue
			case ik.Size > maxsize && maxsize > 0:
				db.Close()
				continue
			}

		}

		err = db.View(func(tx *bolt.Tx) error {

			verr := errors.New("time bucket not exists")

			b := tx.Bucket([]byte(tbucket))
			if b != nil {

				val := b.Get([]byte(keyname))
				if val != nil {
					ik.Date = Endian.Uint64(val)
				}

			} else {
				return verr
			}

			return nil

		})
		if err != nil {
			db.Close()
			return ikeys, err
		}

		if sdcheck {

			switch {
			case ik.Date < minstmp && minstmp > 0:
				db.Close()
				continue
			case ik.Date > maxstmp && maxstmp > 0:
				db.Close()
				continue
			}

		}

		if withvalue && int64(ik.Size) <= vmaxsize {

			err = db.View(func(tx *bolt.Tx) error {

				verr := errors.New("index bucket not exists")

				b := tx.Bucket([]byte(ibucket))
				if b != nil {

					val := b.Get([]byte(keyname))
					if val != nil {
						bval = string(val)
					}

				} else {
					return verr
				}

				return nil

			})
			if err != nil {
				db.Close()
				return ikeys, err
			}

			if bval != "" {

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("bucket not exists")

					b := tx.Bucket([]byte(bval))
					if b != nil {

						val := b.Get([]byte(keyname))
						if val != nil {
							value = val
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

			}

		}

		vhex := make([]byte, hex.EncodedLen(len(value)))
		hex.Encode(vhex, value)

		ik.Value = vhex

		db.Close()

		ikeys = append(ikeys, ik)

	}

	return ikeys, err

}

// AllKeys : search summary file and key names through requested directory
func AllKeys(ibucket string, sbucket string, tbucket string, filemode os.FileMode, timeout time.Duration, opentries int, freelist string, dirpath string, limit uint64, offset uint64, expression string, recursive uint8, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, uniq bool) (ikeys []Keys, err error) {

	var filekeys []string
	var dbkeys []string
	compare := map[string]bool{}

	var k string

	var ik Keys

	var sdcheck bool = false

	iminsize := int64(minsize)
	imaxsize := int64(maxsize)
	iminstmp := int64(minstmp)
	imaxstmp := int64(maxstmp)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	rgxexpression, err := regexp.Compile(expression)
	if err != nil {
		return ikeys, err
	}

	dirpath = filepath.Clean(dirpath)
	url = strings.TrimSuffix(url, "/")

	paths, err := RecursiveDirSearch(dirpath, recursive)
	if err != nil {
		return ikeys, err
	}

	cl := uint64(1)
	co := uint64(1)

	for _, dirname := range paths {

		files, err := ioutil.ReadDir(dirname)
		if err != nil {
			return ikeys, err
		}

		for _, file := range files {

			k = file.Name()

			bname := rgxbolt.MatchString(k)
			cname := rgxcrcbolt.MatchString(k)

			if !file.IsDir() && !bname && !cname {

				if !rgxexpression.MatchString(k) {
					continue
				}

				if co < offset && offset > 0 {
					co++
					continue
				}

				if cl > limit && limit > 0 {
					break
				}

				filename := dirname + "/" + k

				lnfile, err := os.Lstat(filename)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				filekeys = append(filekeys, filename)
				compare[filename] = true

				if stopfirst == 1 {
					stopfirst = 255
					break
				}

				co++
				cl++

			}

			if !file.IsDir() && bname {

				dbname := dirname + "/" + k

				lnfile, err := os.Lstat(dbname)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("index bucket not exists")

					b := tx.Bucket([]byte(ibucket))
					if b != nil {

						pos := b.Cursor()

						for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

							bk := string(inkey)

							if !rgxexpression.MatchString(bk) {
								continue
							}

							if co < offset && offset > 0 {
								co++
								continue
							}

							if cl > limit && limit > 0 {
								break
							}

							filename := dirname + "/" + bk
							dbkeys = append(dbkeys, filename)

							if stopfirst == 1 {
								stopfirst = 255
								break
							}

							co++
							cl++

						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				db.Close()

			}

			if stopfirst == 255 {
				break
			}

			if cl > limit && limit > 0 {
				break
			}

		}

		if stopfirst == 255 {
			break
		}

		if cl > limit && limit > 0 {
			break
		}

	}

	sort.Strings(filekeys)

	for _, filename := range filekeys {

		if sdcheck {

			infile, err := os.Stat(filename)
			if err != nil {
				continue
			}

			fsize := infile.Size()
			fdate := infile.ModTime().Unix()

			switch {
			case fsize < iminsize && minsize > 0:
				continue
			case fsize > imaxsize && maxsize > 0:
				continue
			case fdate < iminstmp && minstmp > 0:
				continue
			case fdate > imaxstmp && maxstmp > 0:
				continue
			}

		}

		filename = strings.TrimPrefix(filename, dirpath+"/")

		if withurl {
			filename = url + "/" + filename
		}

		ik.Key = filename

		ikeys = append(ikeys, ik)

	}

	sort.Strings(dbkeys)

	if uniq {

		for _, filename := range dbkeys {

			if sdcheck {

				var ksize uint64
				var kdate uint64

				keyname := filepath.Base(filename)
				lastpath := filepath.Dir(filename)
				boltname := filepath.Base(lastpath) + ".bolt"
				dbname := lastpath + "/" + boltname

				db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("size bucket not exists")

					b := tx.Bucket([]byte(sbucket))
					if b != nil {

						val := b.Get([]byte(keyname))
						if val != nil {
							ksize = Endian.Uint64(val)
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				if sdcheck {

					switch {
					case ksize < minsize && minsize > 0:
						db.Close()
						continue
					case ksize > maxsize && maxsize > 0:
						db.Close()
						continue
					}

				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("time bucket not exists")

					b := tx.Bucket([]byte(tbucket))
					if b != nil {

						val := b.Get([]byte(keyname))
						if val != nil {
							kdate = Endian.Uint64(val)
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				if sdcheck {

					switch {
					case kdate < minstmp && minstmp > 0:
						db.Close()
						continue
					case kdate > maxstmp && maxstmp > 0:
						db.Close()
						continue
					}

				}

				db.Close()

			}

			if !compare[filename] {

				filename = strings.TrimPrefix(filename, dirpath+"/")

				if withurl {
					filename = url + "/" + filename
				}

				ik.Key = filename

				ikeys = append(ikeys, ik)

			}

		}

	} else {

		for _, filename := range dbkeys {

			if sdcheck {

				var ksize uint64
				var kdate uint64

				keyname := filepath.Base(filename)
				lastpath := filepath.Dir(filename)
				boltname := filepath.Base(lastpath) + ".bolt"
				dbname := lastpath + "/" + boltname

				db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("size bucket not exists")

					b := tx.Bucket([]byte(sbucket))
					if b != nil {

						val := b.Get([]byte(keyname))
						if val != nil {
							ksize = Endian.Uint64(val)
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				if sdcheck {

					switch {
					case ksize < minsize && minsize > 0:
						db.Close()
						continue
					case ksize > maxsize && maxsize > 0:
						db.Close()
						continue
					}

				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("time bucket not exists")

					b := tx.Bucket([]byte(tbucket))
					if b != nil {

						val := b.Get([]byte(keyname))
						if val != nil {
							kdate = Endian.Uint64(val)
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				if sdcheck {

					switch {
					case kdate < minstmp && minstmp > 0:
						db.Close()
						continue
					case kdate > maxstmp && maxstmp > 0:
						db.Close()
						continue
					}

				}

				db.Close()

			}

			filename = strings.TrimPrefix(filename, dirpath+"/")

			if withurl {
				filename = url + "/" + filename
			}

			ik.Key = filename

			ikeys = append(ikeys, ik)

		}

	}

	return ikeys, err

}

// AllKeysInfo : search summary file and key names with info through requested directory
func AllKeysInfo(ibucket string, sbucket string, tbucket string, filemode os.FileMode, timeout time.Duration, opentries int, freelist string, dirpath string, limit uint64, offset uint64, expression string, recursive uint8, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, uniq bool) (ikeys []KeysInfo, err error) {

	var filekeys []string
	var dbkeys []string
	compare := map[string]bool{}

	var k string

	var ik KeysInfo

	var sdcheck bool = false

	iminsize := int64(minsize)
	imaxsize := int64(maxsize)
	iminstmp := int64(minstmp)
	imaxstmp := int64(maxstmp)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	rgxexpression, err := regexp.Compile(expression)
	if err != nil {
		return ikeys, err
	}

	dirpath = filepath.Clean(dirpath)
	url = strings.TrimSuffix(url, "/")

	paths, err := RecursiveDirSearch(dirpath, recursive)
	if err != nil {
		return ikeys, err
	}

	cl := uint64(1)
	co := uint64(1)

	for _, dirname := range paths {

		files, err := ioutil.ReadDir(dirname)
		if err != nil {
			return ikeys, err
		}

		for _, file := range files {

			k = file.Name()

			bname := rgxbolt.MatchString(k)
			cname := rgxcrcbolt.MatchString(k)

			if !file.IsDir() && !bname && !cname {

				if !rgxexpression.MatchString(k) {
					continue
				}

				if co < offset && offset > 0 {
					co++
					continue
				}

				if cl > limit && limit > 0 {
					break
				}

				filename := dirname + "/" + k

				lnfile, err := os.Lstat(filename)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				filekeys = append(filekeys, filename)
				compare[filename] = true

				if stopfirst == 1 {
					stopfirst = 255
					break
				}

				co++
				cl++

			}

			if !file.IsDir() && bname {

				dbname := dirname + "/" + k

				lnfile, err := os.Lstat(dbname)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("index bucket not exists")

					b := tx.Bucket([]byte(ibucket))
					if b != nil {

						pos := b.Cursor()

						for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

							bk := string(inkey)

							if !rgxexpression.MatchString(bk) {
								continue
							}

							if co < offset && offset > 0 {
								co++
								continue
							}

							if cl > limit && limit > 0 {
								break
							}

							filename := dirname + "/" + bk
							dbkeys = append(dbkeys, filename)

							if stopfirst == 1 {
								stopfirst = 255
								break
							}

							co++
							cl++

						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				db.Close()

			}

			if stopfirst == 255 {
				break
			}

			if cl > limit && limit > 0 {
				break
			}

		}

		if stopfirst == 255 {
			break
		}

		if cl > limit && limit > 0 {
			break
		}

	}

	sort.Strings(filekeys)

	for _, filename := range filekeys {

		infile, err := os.Stat(filename)
		if err != nil {
			continue
		}

		fsize := infile.Size()
		fdate := infile.ModTime().Unix()

		if sdcheck {

			switch {
			case fsize < iminsize && minsize > 0:
				continue
			case fsize > imaxsize && maxsize > 0:
				continue
			case fdate < iminstmp && minstmp > 0:
				continue
			case fdate > imaxstmp && maxstmp > 0:
				continue
			}

		}

		filename = strings.TrimPrefix(filename, dirpath+"/")

		if withurl {
			filename = url + "/" + filename
		}

		ik.Key = filename
		ik.Type = 0
		ik.Size = uint64(fsize)
		ik.Date = uint64(fdate)

		ikeys = append(ikeys, ik)

	}

	sort.Strings(dbkeys)

	if uniq {

		for _, filename := range dbkeys {

			keyname := filepath.Base(filename)
			lastpath := filepath.Dir(filename)
			boltname := filepath.Base(lastpath) + ".bolt"
			dbname := lastpath + "/" + boltname

			if !compare[filename] {

				filename = strings.TrimPrefix(filename, dirpath+"/")

				if withurl {
					filename = url + "/" + filename
				}

				ik.Key = filename
				ik.Type = 1

				db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("size bucket not exists")

					b := tx.Bucket([]byte(sbucket))
					if b != nil {

						val := b.Get([]byte(keyname))
						if val != nil {
							ik.Size = Endian.Uint64(val)
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				if sdcheck {

					switch {
					case ik.Size < minsize && minsize > 0:
						db.Close()
						continue
					case ik.Size > maxsize && maxsize > 0:
						db.Close()
						continue
					}

				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("time bucket not exists")

					b := tx.Bucket([]byte(tbucket))
					if b != nil {

						val := b.Get([]byte(keyname))
						if val != nil {
							ik.Date = Endian.Uint64(val)
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				if sdcheck {

					switch {
					case ik.Date < minstmp && minstmp > 0:
						db.Close()
						continue
					case ik.Date > maxstmp && maxstmp > 0:
						db.Close()
						continue
					}

				}

				db.Close()

				ikeys = append(ikeys, ik)

			}

		}

	} else {

		for _, filename := range dbkeys {

			keyname := filepath.Base(filename)
			lastpath := filepath.Dir(filename)
			boltname := filepath.Base(lastpath) + ".bolt"
			dbname := lastpath + "/" + boltname

			filename = strings.TrimPrefix(filename, dirpath+"/")

			if withurl {
				filename = url + "/" + filename
			}

			ik.Key = filename
			ik.Type = 1

			db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
			if err != nil {
				return ikeys, err
			}

			err = db.View(func(tx *bolt.Tx) error {

				verr := errors.New("size bucket not exists")

				b := tx.Bucket([]byte(sbucket))
				if b != nil {

					val := b.Get([]byte(keyname))
					if val != nil {
						ik.Size = Endian.Uint64(val)
					}

				} else {
					return verr
				}

				return nil

			})
			if err != nil {
				db.Close()
				return ikeys, err
			}

			if sdcheck {

				switch {
				case ik.Size < minsize && minsize > 0:
					db.Close()
					continue
				case ik.Size > maxsize && maxsize > 0:
					db.Close()
					continue
				}

			}

			err = db.View(func(tx *bolt.Tx) error {

				verr := errors.New("time bucket not exists")

				b := tx.Bucket([]byte(tbucket))
				if b != nil {

					val := b.Get([]byte(keyname))
					if val != nil {
						ik.Date = Endian.Uint64(val)
					}

				} else {
					return verr
				}

				return nil

			})
			if err != nil {
				db.Close()
				return ikeys, err
			}

			if sdcheck {

				switch {
				case ik.Date < minstmp && minstmp > 0:
					db.Close()
					continue
				case ik.Date > maxstmp && maxstmp > 0:
					db.Close()
					continue
				}

			}

			db.Close()

			ikeys = append(ikeys, ik)

		}

	}

	return ikeys, err

}

// AllKeysSearch : search summary file and key names/names with values through requested directory
func AllKeysSearch(ibucket string, sbucket string, tbucket string, filemode os.FileMode, timeout time.Duration, opentries int, freelist string, dirpath string, limit uint64, offset uint64, expression string, recursive uint8, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withvalue bool, vmaxsize int64, uniq bool) (ikeys []KeysSearch, err error) {

	var filekeys []string
	var dbkeys []string
	compare := map[string]bool{}

	var k string

	var ik KeysSearch

	var sdcheck bool = false

	iminsize := int64(minsize)
	imaxsize := int64(maxsize)
	iminstmp := int64(minstmp)
	imaxstmp := int64(maxstmp)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	rgxexpression, err := regexp.Compile(expression)
	if err != nil {
		return ikeys, err
	}

	dirpath = filepath.Clean(dirpath)
	url = strings.TrimSuffix(url, "/")

	paths, err := RecursiveDirSearch(dirpath, recursive)
	if err != nil {
		return ikeys, err
	}

	cl := uint64(1)
	co := uint64(1)

	for _, dirname := range paths {

		files, err := ioutil.ReadDir(dirname)
		if err != nil {
			return ikeys, err
		}

		for _, file := range files {

			k = file.Name()

			bname := rgxbolt.MatchString(k)
			cname := rgxcrcbolt.MatchString(k)

			if !file.IsDir() && !bname && !cname {

				if !rgxexpression.MatchString(k) {
					continue
				}

				if co < offset && offset > 0 {
					co++
					continue
				}

				if cl > limit && limit > 0 {
					break
				}

				filename := dirname + "/" + k

				lnfile, err := os.Lstat(filename)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				filekeys = append(filekeys, filename)
				compare[filename] = true

				if stopfirst == 1 {
					stopfirst = 255
					break
				}

				co++
				cl++

			}

			if !file.IsDir() && bname {

				dbname := dirname + "/" + k

				lnfile, err := os.Lstat(dbname)
				if err != nil {
					continue
				}

				if lnfile.Mode()&os.ModeType != 0 {
					continue
				}

				db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("index bucket not exists")

					b := tx.Bucket([]byte(ibucket))
					if b != nil {

						pos := b.Cursor()

						for inkey, _ := pos.First(); inkey != nil; inkey, _ = pos.Next() {

							bk := string(inkey)

							if !rgxexpression.MatchString(bk) {
								continue
							}

							if co < offset && offset > 0 {
								co++
								continue
							}

							if cl > limit && limit > 0 {
								break
							}

							filename := dirname + "/" + bk
							dbkeys = append(dbkeys, filename)

							if stopfirst == 1 {
								stopfirst = 255
								break
							}

							co++
							cl++

						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				db.Close()

			}

			if stopfirst == 255 {
				break
			}

			if cl > limit && limit > 0 {
				break
			}

		}

		if stopfirst == 255 {
			break
		}

		if cl > limit && limit > 0 {
			break
		}

	}

	sort.Strings(filekeys)

	for _, filename := range filekeys {

		var value []byte

		infile, err := os.Stat(filename)
		if err != nil {
			continue
		}

		fsize := infile.Size()
		fdate := infile.ModTime().Unix()

		if sdcheck {

			switch {
			case fsize < iminsize && minsize > 0:
				continue
			case fsize > imaxsize && maxsize > 0:
				continue
			case fdate < iminstmp && minstmp > 0:
				continue
			case fdate > imaxstmp && maxstmp > 0:
				continue
			}

		}

		if withvalue && fsize <= vmaxsize {

			value, err = ioutil.ReadFile(filename)
			if err != nil {
				return ikeys, err
			}

		}

		filename = strings.TrimPrefix(filename, dirpath+"/")

		if withurl {
			filename = url + "/" + filename
		}

		ik.Key = filename
		ik.Type = 0
		ik.Size = uint64(fsize)
		ik.Date = uint64(fdate)

		vhex := make([]byte, hex.EncodedLen(len(value)))
		hex.Encode(vhex, value)

		ik.Value = vhex

		ikeys = append(ikeys, ik)

	}

	sort.Strings(dbkeys)

	if uniq {

		for _, filename := range dbkeys {

			var value []byte = nil
			var bval string = ""

			keyname := filepath.Base(filename)
			lastpath := filepath.Dir(filename)
			boltname := filepath.Base(lastpath) + ".bolt"
			dbname := lastpath + "/" + boltname

			if !compare[filename] {

				filename = strings.TrimPrefix(filename, dirpath+"/")

				if withurl {
					filename = url + "/" + filename
				}

				ik.Key = filename
				ik.Type = 1

				db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
				if err != nil {
					return ikeys, err
				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("size bucket not exists")

					b := tx.Bucket([]byte(sbucket))
					if b != nil {

						val := b.Get([]byte(keyname))
						if val != nil {
							ik.Size = Endian.Uint64(val)
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				if sdcheck {

					switch {
					case ik.Size < minsize && minsize > 0:
						db.Close()
						continue
					case ik.Size > maxsize && maxsize > 0:
						db.Close()
						continue
					}

				}

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("time bucket not exists")

					b := tx.Bucket([]byte(tbucket))
					if b != nil {

						val := b.Get([]byte(keyname))
						if val != nil {
							ik.Date = Endian.Uint64(val)
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				if sdcheck {

					switch {
					case ik.Date < minstmp && minstmp > 0:
						db.Close()
						continue
					case ik.Date > maxstmp && maxstmp > 0:
						db.Close()
						continue
					}

				}

				if withvalue && int64(ik.Size) <= vmaxsize {

					err = db.View(func(tx *bolt.Tx) error {

						verr := errors.New("index bucket not exists")

						b := tx.Bucket([]byte(ibucket))
						if b != nil {

							val := b.Get([]byte(keyname))
							if val != nil {
								bval = string(val)
							}

						} else {
							return verr
						}

						return nil

					})
					if err != nil {
						db.Close()
						return ikeys, err
					}

					if bval != "" {

						err = db.View(func(tx *bolt.Tx) error {

							verr := errors.New("bucket not exists")

							b := tx.Bucket([]byte(bval))
							if b != nil {

								val := b.Get([]byte(keyname))
								if val != nil {
									value = val
								}

							} else {
								return verr
							}

							return nil

						})
						if err != nil {
							db.Close()
							return ikeys, err
						}

					}

				}

				vhex := make([]byte, hex.EncodedLen(len(value)))
				hex.Encode(vhex, value)

				ik.Value = vhex

				db.Close()

				ikeys = append(ikeys, ik)

			}

		}

	} else {

		for _, filename := range dbkeys {

			var value []byte = nil
			var bval string = ""

			keyname := filepath.Base(filename)
			lastpath := filepath.Dir(filename)
			boltname := filepath.Base(lastpath) + ".bolt"
			dbname := lastpath + "/" + boltname

			filename = strings.TrimPrefix(filename, dirpath+"/")

			if withurl {
				filename = url + "/" + filename
			}

			ik.Key = filename
			ik.Type = 1

			db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
			if err != nil {
				return ikeys, err
			}

			err = db.View(func(tx *bolt.Tx) error {

				verr := errors.New("size bucket not exists")

				b := tx.Bucket([]byte(sbucket))
				if b != nil {

					val := b.Get([]byte(keyname))
					if val != nil {
						ik.Size = Endian.Uint64(val)
					}

				} else {
					return verr
				}

				return nil

			})
			if err != nil {
				db.Close()
				return ikeys, err
			}

			if sdcheck {

				switch {
				case ik.Size < minsize && minsize > 0:
					db.Close()
					continue
				case ik.Size > maxsize && maxsize > 0:
					db.Close()
					continue
				}

			}

			err = db.View(func(tx *bolt.Tx) error {

				verr := errors.New("time bucket not exists")

				b := tx.Bucket([]byte(tbucket))
				if b != nil {

					val := b.Get([]byte(keyname))
					if val != nil {
						ik.Date = Endian.Uint64(val)
					}

				} else {
					return verr
				}

				return nil

			})
			if err != nil {
				db.Close()
				return ikeys, err
			}

			if sdcheck {

				switch {
				case ik.Date < minstmp && minstmp > 0:
					db.Close()
					continue
				case ik.Date > maxstmp && maxstmp > 0:
					db.Close()
					continue
				}

			}

			if withvalue && int64(ik.Size) <= vmaxsize {

				err = db.View(func(tx *bolt.Tx) error {

					verr := errors.New("index bucket not exists")

					b := tx.Bucket([]byte(ibucket))
					if b != nil {

						val := b.Get([]byte(keyname))
						if val != nil {
							bval = string(val)
						}

					} else {
						return verr
					}

					return nil

				})
				if err != nil {
					db.Close()
					return ikeys, err
				}

				if bval != "" {

					err = db.View(func(tx *bolt.Tx) error {

						verr := errors.New("bucket not exists")

						b := tx.Bucket([]byte(bval))
						if b != nil {

							val := b.Get([]byte(keyname))
							if val != nil {
								value = val
							}

						} else {
							return verr
						}

						return nil

					})
					if err != nil {
						db.Close()
						return ikeys, err
					}

				}

			}

			vhex := make([]byte, hex.EncodedLen(len(value)))
			hex.Encode(vhex, value)

			ik.Value = vhex

			db.Close()

			ikeys = append(ikeys, ik)

		}

	}

	return ikeys, err

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

// RecursiveDirSearch : search directories names through requested directory with maximum available recursion level = 3
func RecursiveDirSearch(dirpath string, recursive uint8) (paths []string, err error) {

	var r1paths []string
	var r2paths []string

	paths = append(paths, dirpath)

	if recursive > 3 {
		recursive = 3
	}

	if recursive > 0 {

		rcnt := uint8(0)

		r1allfiles, err := ioutil.ReadDir(dirpath)
		if err != nil {
			return paths, err
		}

		for _, dir := range r1allfiles {

			if dir.IsDir() && dir.Name() != "." && dir.Name() != ".." {

				dirname := dirpath + "/" + dir.Name()
				paths = append(paths, dirname)
				r1paths = append(r1paths, dirname)

			}

		}

		rcnt++

		if rcnt < recursive {

			for _, dirpath := range r1paths {

				r2allfiles, err := ioutil.ReadDir(dirpath)
				if err != nil {
					return paths, err
				}

				for _, dir := range r2allfiles {

					if dir.IsDir() && dir.Name() != "." && dir.Name() != ".." {

						dirname := dirpath + "/" + dir.Name()
						paths = append(paths, dirname)
						r2paths = append(r2paths, dirname)

					}

				}

			}

		}

		rcnt++

		if rcnt < recursive {

			for _, dirpath := range r2paths {

				r3allfiles, err := ioutil.ReadDir(dirpath)
				if err != nil {
					return paths, err
				}

				for _, dir := range r3allfiles {

					if dir.IsDir() && dir.Name() != "." && dir.Name() != ".." {

						dirname := dirpath + "/" + dir.Name()
						paths = append(paths, dirname)

					}

				}

			}

		}

	}

	return paths, err

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
