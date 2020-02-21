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
	"bytes"
	"errors"
	"github.com/eltaline/bolt"
	"github.com/eltaline/nutsdb"
	"io/ioutil"
	"os"
	"time"
)

// DB Helpers

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

// NDBInsert : NutsDB insert key function
func NDBInsert(db *nutsdb.DB, bucket string, key []byte, value []byte, ttl uint32) error {

	nerr := db.Update(func(tx *nutsdb.Tx) error {

		err := tx.Put(bucket, key, value, ttl)
		if err != nil {
			return err
		}

		return nil

	})

	if nerr != nil {
		return nerr
	}

	return nil

}

// NDBDelete : NutsDB delete key function
func NDBDelete(db *nutsdb.DB, bucket string, key []byte) error {

	nerr := db.Update(func(tx *nutsdb.Tx) error {

		err := tx.Delete(bucket, key)
		if err != nil {
			return err
		}

		return nil

	})

	if nerr != nil {
		return nerr
	}

	return nil

}

// NDBMerge : NutsDB merge compaction function
func NDBMerge(db *nutsdb.DB, dir string) error {

	var err error

	err = db.Merge()
	if err != nil {
		return err
	}

	segs, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, seg := range segs {

		sn := seg.Name()
		ss := seg.Size()

		fn := dir + "/" + sn

		emptyBuffer := make([]byte, ss)

		segmentBuffer, err := ioutil.ReadFile(fn)
		if err != nil {
			return err
		}

		if segmentBuffer != nil {

			if bytes.Equal(emptyBuffer, segmentBuffer) {
				err = RemoveSegment(fn)
				if err != nil {
					return err
				}
			}

		}

	}

	return nil

}

// DBGetVal : get value of requested key from bucket
func DBGetVal(db *bolt.DB, bucket string, key []byte) (data []byte, err error) {

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("bucket not exists")

		b := tx.Bucket([]byte(bucket))
		if b != nil {

			val := b.GetOffset(key, 36)
			if val != nil {
				data = val
			}

		} else {
			return verr
		}

		return nil

	})

	return data, err

}

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

// KeyGetVal : get value of requested key in index/size/time bucket
func KeyGetVal(db *bolt.DB, xbucket string, key []byte) (data []byte, err error) {

	err = db.View(func(tx *bolt.Tx) error {

		verr := errors.New("index/size/time bucket not exists")

		b := tx.Bucket([]byte(xbucket))
		if b != nil {

			val := b.Get(key)
			if val != nil {
				data = val
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
