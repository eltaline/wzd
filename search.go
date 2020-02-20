package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/eltaline/go-waitgroup"
	"github.com/eltaline/nutsdb"
	"hash/crc64"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Search Handlers

// Sort Handlers

// Sort Ascending Handlers

// Len : len sort
func (e KeysListAsc) Len() int {
	return len(e)
}

// Less : less sort
func (e KeysListAsc) Less(i, j int) bool {
	return e[i].Key < e[j].Key
}

// Swap : swap sort
func (e KeysListAsc) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

// Len : len sort
func (e KeysInfoListAsc) Len() int {
	return len(e)
}

// Less : less sort
func (e KeysInfoListAsc) Less(i, j int) bool {
	return e[i].Key < e[j].Key
}

// Swap : swap sort
func (e KeysInfoListAsc) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

// Len : len sort
func (e KeysSearchListAsc) Len() int {
	return len(e)
}

// Less : less sort
func (e KeysSearchListAsc) Less(i, j int) bool {
	return e[i].Key < e[j].Key
}

// Swap : swap sort
func (e KeysSearchListAsc) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

// Sort Descending Handlers

// Len : len sort
func (e KeysListDsc) Len() int {
	return len(e)
}

// Less : less sort
func (e KeysListDsc) Less(i, j int) bool {
	return e[i].Key > e[j].Key
}

// Swap : swap sort
func (e KeysListDsc) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

// Len : len sort
func (e KeysInfoListDsc) Len() int {
	return len(e)
}

// Less : less sort
func (e KeysInfoListDsc) Less(i, j int) bool {
	return e[i].Key > e[j].Key
}

// Swap : swap sort
func (e KeysInfoListDsc) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

// Len : len sort
func (e KeysSearchListDsc) Len() int {
	return len(e)
}

// Less : less sort
func (e KeysSearchListDsc) Less(i, j int) bool {
	return e[i].Key > e[j].Key
}

// Swap : swap sort
func (e KeysSearchListDsc) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

// Names/Count Helpers

// FileKeys : search file names through requested directory
func FileKeys(ndb *nutsdb.DB, base string, dirpath string, msort uint8, offset int, limit int, prefix string, expression string, recursive int, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withjoin map[string]int, searchthreads int, searchtimeout int) ([]Keys, int, int, error) {

	var key sync.Mutex

	var ikeys []Keys
	var skeys []Keys

	var sdcheck bool = false

	bprefix := []byte("f:" + prefix)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	dirpath = filepath.Clean(dirpath)
	// url = strings.TrimSuffix(url, "/")

	paths, err := RTree(dirpath, withjoin, recursive)
	if err != nil {
		return ikeys, offset, limit, err
	}

	pkeys := make([]string, 0, len(paths))
	for pk := range paths {
		pkeys = append(pkeys, pk)
	}

	sort.Strings(pkeys)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(searchtimeout)*time.Second)
	defer cancel()

	if offset > 0 {
		searchthreads = 1
	}

	qwg, ctx := waitgroup.NewErrorGroup(ctx, searchthreads)

Main:

	for _, idirname := range pkeys {

		select {
		case <-ctx.Done():
			err = ctx.Err()
			break Main
		default:
		}

		dirname := idirname
		dcrc := paths[dirname]

		qwg.Add(func() error {

			qoffset := offset

			cl := 1

			vdirname := strings.TrimPrefix(dirname, base) + "/"

			nbucket := strconv.FormatUint(dcrc, 16)

			nerr := ndb.View(func(tx *nutsdb.Tx) error {

				var err error

				var entries nutsdb.Entries

				var off int

				switch {
				case expression != "(.+)" || (prefix != "" && expression != "(.+)"):
					entries, off, err = tx.PrefixSearchScan(nbucket, bprefix, expression, qoffset, limit)
				default:
					entries, off, err = tx.PrefixScan(nbucket, bprefix, qoffset, limit)
				}

				if entries == nil {

					key.Lock()
					offset = qoffset - off
					key.Unlock()

					return nil

				}

				if err != nil {
					return err
				}

				err = nil

				key.Lock()
				offset = offset - off
				key.Unlock()

			SubMain:

				for _, entry := range entries {

					select {
					case <-ctx.Done():
						err = ctx.Err()
						break SubMain
					default:
					}

					if cl > limit && limit > 0 {
						break
					}

					var ik Keys
					var ev RawKeysData

					kname := strings.TrimPrefix(string(entry.Key), "f:")

					if sdcheck {

						err = binary.Read(bytes.NewReader(entry.Value), Endian, &ev)
						if err != nil {
							return err
						}

						switch {
						case ev.Size < minsize && minsize > 0:
							continue
						case ev.Size > maxsize && maxsize > 0:
							continue
						case ev.Date < minstmp && minstmp > 0:
							continue
						case ev.Date > maxstmp && maxstmp > 0:
							continue
						}

					}

					kname = strings.TrimPrefix(vdirname+kname, "/")

					if withurl {
						kname = url + "/" + kname
					}

					ik.Key = kname
					ik.Type = 0

					key.Lock()
					ikeys = append(ikeys, ik)
					key.Unlock()

					if stopfirst == 1 {
						break
					}

					cl++

				}

				if err != nil {
					return err
				}

				return nil

			})

			if nerr != nil {
				cancel()
				return nerr
			}

			return nil

		})

	}

	if err != nil {
		return ikeys, offset, limit, err
	}

	if werr := qwg.Wait(); werr != nil {
		return ikeys, offset, limit, werr
	}

	switch {
	case msort == 0:
		sort.Sort(KeysListAsc(ikeys))
	case msort == 1:
		sort.Sort(KeysListDsc(ikeys))
	}

	if limit > 0 || stopfirst == 1 {

		cl := 1

		for _, ssk := range ikeys {

			if cl > limit && limit > 0 {
				break
			}

			skeys = append(skeys, ssk)

			if stopfirst == 1 {
				break
			}

			cl++

		}

		return skeys, offset, cl, err

	}

	return ikeys, offset, limit, err

}

// FileKeysInfo : search file names with info through requested directory
func FileKeysInfo(ndb *nutsdb.DB, base string, dirpath string, msort uint8, offset int, limit int, prefix string, expression string, recursive int, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withjoin map[string]int, searchthreads int, searchtimeout int) ([]KeysInfo, int, int, error) {

	var key sync.Mutex

	var ikeys []KeysInfo
	var skeys []KeysInfo

	var sdcheck bool = false

	bprefix := []byte("f:" + prefix)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	dirpath = filepath.Clean(dirpath)
	// url = strings.TrimSuffix(url, "/")

	paths, err := RTree(dirpath, withjoin, recursive)
	if err != nil {
		return ikeys, offset, limit, err
	}

	pkeys := make([]string, 0, len(paths))
	for pk := range paths {
		pkeys = append(pkeys, pk)
	}

	sort.Strings(pkeys)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(searchtimeout)*time.Second)
	defer cancel()

	if offset > 0 {
		searchthreads = 1
	}

	qwg, ctx := waitgroup.NewErrorGroup(ctx, searchthreads)

Main:

	for _, idirname := range pkeys {

		select {
		case <-ctx.Done():
			err = ctx.Err()
			break Main
		default:
		}

		dirname := idirname
		dcrc := paths[dirname]

		qwg.Add(func() error {

			qoffset := offset

			cl := 1

			vdirname := strings.TrimPrefix(dirname, base) + "/"

			nbucket := strconv.FormatUint(dcrc, 16)

			nerr := ndb.View(func(tx *nutsdb.Tx) error {

				var err error

				var entries nutsdb.Entries

				var off int

				switch {
				case expression != "(.+)" || (prefix != "" && expression != "(.+)"):
					entries, off, err = tx.PrefixSearchScan(nbucket, bprefix, expression, qoffset, limit)
				default:
					entries, off, err = tx.PrefixScan(nbucket, bprefix, qoffset, limit)
				}

				if entries == nil {

					key.Lock()
					offset = qoffset - off
					key.Unlock()

					return nil

				}

				if err != nil {
					return err
				}

				err = nil

				key.Lock()
				offset = offset - off
				key.Unlock()

			SubMain:

				for _, entry := range entries {

					select {
					case <-ctx.Done():
						err = ctx.Err()
						break SubMain
					default:
					}

					if cl > limit && limit > 0 {
						break
					}

					var ik KeysInfo
					var ev RawKeysData

					kname := strings.TrimPrefix(string(entry.Key), "f:")

					err = binary.Read(bytes.NewReader(entry.Value), Endian, &ev)
					if err != nil {
						return err
					}

					if sdcheck {

						switch {
						case ev.Size < minsize && minsize > 0:
							continue
						case ev.Size > maxsize && maxsize > 0:
							continue
						case ev.Date < minstmp && minstmp > 0:
							continue
						case ev.Date > maxstmp && maxstmp > 0:
							continue
						}

					}

					kname = strings.TrimPrefix(vdirname+kname, "/")

					if withurl {
						kname = url + "/" + kname
					}

					ik.Key = kname
					ik.Type = 0
					ik.Size = ev.Size
					ik.Date = ev.Date

					key.Lock()
					ikeys = append(ikeys, ik)
					key.Unlock()

					if stopfirst == 1 {
						break
					}

					cl++

				}

				if err != nil {
					return err
				}

				return nil

			})

			if nerr != nil {
				cancel()
				return nerr
			}

			return nil

		})

	}

	if err != nil {
		return ikeys, offset, limit, err
	}

	if werr := qwg.Wait(); werr != nil {
		return ikeys, offset, limit, werr
	}

	switch {
	case msort == 0:
		sort.Sort(KeysInfoListAsc(ikeys))
	case msort == 1:
		sort.Sort(KeysInfoListDsc(ikeys))
	}

	if limit > 0 || stopfirst == 1 {

		cl := 1

		for _, ssk := range ikeys {

			if cl > limit && limit > 0 {
				break
			}

			skeys = append(skeys, ssk)

			if stopfirst == 1 {
				break
			}

			cl++

		}

		return skeys, offset, cl, err

	}

	return ikeys, offset, limit, err

}

// FileKeysSearch : search file names/names with values through requested directory
func FileKeysSearch(ndb *nutsdb.DB, base string, dirpath string, msort uint8, offset int, limit int, prefix string, expression string, recursive int, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withjoin map[string]int, withvalue bool, vmaxsize int64, searchthreads int, searchtimeout int) ([]KeysSearch, int, int, error) {

	var key sync.Mutex

	var ikeys []KeysSearch
	var skeys []KeysSearch

	imaxsize := uint64(vmaxsize)

	var sdcheck bool = false

	bprefix := []byte("f:" + prefix)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	dirpath = filepath.Clean(dirpath)
	// url = strings.TrimSuffix(url, "/")

	paths, err := RTree(dirpath, withjoin, recursive)
	if err != nil {
		return ikeys, offset, limit, err
	}

	pkeys := make([]string, 0, len(paths))
	for pk := range paths {
		pkeys = append(pkeys, pk)
	}

	sort.Strings(pkeys)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(searchtimeout)*time.Second)
	defer cancel()

	if offset > 0 {
		searchthreads = 1
	}

	qwg, ctx := waitgroup.NewErrorGroup(ctx, searchthreads)

Main:

	for _, idirname := range pkeys {

		select {
		case <-ctx.Done():
			err = ctx.Err()
			break Main
		default:
		}

		dirname := idirname
		dcrc := paths[dirname]

		qwg.Add(func() error {

			qoffset := offset

			cl := 1

			vdirname := strings.TrimPrefix(dirname, base) + "/"

			nbucket := strconv.FormatUint(dcrc, 16)

			nerr := ndb.View(func(tx *nutsdb.Tx) error {

				var err error

				var entries nutsdb.Entries

				var off int

				switch {
				case expression != "(.+)" || (prefix != "" && expression != "(.+)"):
					entries, off, err = tx.PrefixSearchScan(nbucket, bprefix, expression, qoffset, limit)
				default:
					entries, off, err = tx.PrefixScan(nbucket, bprefix, qoffset, limit)
				}

				if entries == nil {

					key.Lock()
					offset = qoffset - off
					key.Unlock()

					return nil

				}

				if err != nil {
					return err
				}

				err = nil

				key.Lock()
				offset = offset - off
				key.Unlock()

			SubMain:

				for _, entry := range entries {

					select {
					case <-ctx.Done():
						err = ctx.Err()
						break SubMain
					default:
					}

					if cl > limit && limit > 0 {
						break
					}

					var ik KeysSearch
					var ev RawKeysData

					kname := strings.TrimPrefix(string(entry.Key), "f:")

					err = binary.Read(bytes.NewReader(entry.Value), Endian, &ev)
					if err != nil {
						return err
					}

					if sdcheck {

						switch {
						case ev.Size < minsize && minsize > 0:
							continue
						case ev.Size > maxsize && maxsize > 0:
							continue
						case ev.Date < minstmp && minstmp > 0:
							continue
						case ev.Date > maxstmp && maxstmp > 0:
							continue
						}

					}

					if withvalue && ev.Size <= imaxsize {

						filename := dirname + "/" + kname

						if !FileExists(filename) {
							continue
						}

						value, err := ioutil.ReadFile(filename)
						if err != nil {
							return err
						}

						if value != nil {
							ik.Value = hex.EncodeToString(value)
						}

					}

					kname = strings.TrimPrefix(vdirname+kname, "/")

					if withurl {
						kname = url + "/" + kname
					}

					ik.Key = kname
					ik.Type = 0
					ik.Size = ev.Size
					ik.Date = ev.Date

					key.Lock()
					ikeys = append(ikeys, ik)
					key.Unlock()

					if stopfirst == 1 {
						break
					}

					cl++

				}

				if err != nil {
					return err
				}

				return nil

			})

			if nerr != nil {
				cancel()
				return nerr
			}

			return nil

		})

	}

	if err != nil {
		return ikeys, offset, limit, err
	}

	if werr := qwg.Wait(); werr != nil {
		return ikeys, offset, limit, werr
	}

	switch {
	case msort == 0:
		sort.Sort(KeysSearchListAsc(ikeys))
	case msort == 1:
		sort.Sort(KeysSearchListDsc(ikeys))
	}

	if limit > 0 || stopfirst == 1 {

		cl := 1

		for _, ssk := range ikeys {

			if cl > limit && limit > 0 {
				break
			}

			skeys = append(skeys, ssk)

			if stopfirst == 1 {
				break
			}

			cl++

		}

		return skeys, offset, cl, err

	}

	return ikeys, offset, limit, err

}

// DBKeys : search key names through requested directory
func DBKeys(ndb *nutsdb.DB, base string, dirpath string, msort uint8, offset int, limit int, prefix string, expression string, recursive int, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withjoin map[string]int, searchthreads int, searchtimeout int) ([]Keys, error) {

	var key sync.Mutex

	var ikeys []Keys
	var skeys []Keys

	var sdcheck bool = false

	bprefix := []byte("b:" + prefix)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	dirpath = filepath.Clean(dirpath)
	// url = strings.TrimSuffix(url, "/")

	paths, err := RTree(dirpath, withjoin, recursive)
	if err != nil {
		return ikeys, err
	}

	pkeys := make([]string, 0, len(paths))
	for pk := range paths {
		pkeys = append(pkeys, pk)
	}

	sort.Strings(pkeys)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(searchtimeout)*time.Second)
	defer cancel()

	if offset > 0 {
		searchthreads = 1
	}

	qwg, ctx := waitgroup.NewErrorGroup(ctx, searchthreads)

Main:

	for _, idirname := range pkeys {

		select {
		case <-ctx.Done():
			err = ctx.Err()
			break Main
		default:
		}

		dirname := idirname
		dcrc := paths[dirname]

		qwg.Add(func() error {

			qoffset := offset

			cl := 1

			vdirname := strings.TrimPrefix(dirname, base) + "/"

			nbucket := strconv.FormatUint(dcrc, 16)

			nerr := ndb.View(func(tx *nutsdb.Tx) error {

				var err error

				var entries nutsdb.Entries

				var off int

				switch {
				case expression != "(.+)" || (prefix != "" && expression != "(.+)"):
					entries, off, err = tx.PrefixSearchScan(nbucket, bprefix, expression, qoffset, limit)
				default:
					entries, off, err = tx.PrefixScan(nbucket, bprefix, qoffset, limit)
				}

				if entries == nil {

					key.Lock()
					offset = qoffset - off
					key.Unlock()

					return nil

				}

				if err != nil {
					return err
				}

				err = nil

				key.Lock()
				offset = offset - off
				key.Unlock()

			SubMain:

				for _, entry := range entries {

					select {
					case <-ctx.Done():
						err = ctx.Err()
						break SubMain
					default:
					}

					if cl > limit && limit > 0 {
						break
					}

					var ik Keys
					var ev RawKeysData

					kname := strings.TrimPrefix(string(entry.Key), "b:")

					if sdcheck {

						err = binary.Read(bytes.NewReader(entry.Value), Endian, &ev)
						if err != nil {
							return err
						}

						switch {
						case ev.Size < minsize && minsize > 0:
							continue
						case ev.Size > maxsize && maxsize > 0:
							continue
						case ev.Date < minstmp && minstmp > 0:
							continue
						case ev.Date > maxstmp && maxstmp > 0:
							continue
						}

					}

					kname = strings.TrimPrefix(vdirname+kname, "/")

					if withurl {
						kname = url + "/" + kname
					}

					ik.Key = kname
					ik.Type = 1

					key.Lock()
					ikeys = append(ikeys, ik)
					key.Unlock()

					if stopfirst == 1 {
						break
					}

					cl++

				}

				if err != nil {
					return err
				}

				return nil

			})

			if nerr != nil {
				cancel()
				return nerr
			}

			return nil

		})

	}

	if err != nil {
		return ikeys, err
	}

	if werr := qwg.Wait(); werr != nil {
		return ikeys, werr
	}

	switch {
	case msort == 0:
		sort.Sort(KeysListAsc(ikeys))
	case msort == 1:
		sort.Sort(KeysListDsc(ikeys))
	}

	if limit > 0 || stopfirst == 1 {

		cl := 1

		for _, ssk := range ikeys {

			if cl > limit && limit > 0 {
				break
			}

			skeys = append(skeys, ssk)

			if stopfirst == 1 {
				break
			}

			cl++

		}

		return skeys, err

	}

	return ikeys, err

}

// DBKeysInfo : search key names with info through requested directory
func DBKeysInfo(ndb *nutsdb.DB, base string, dirpath string, msort uint8, offset int, limit int, prefix string, expression string, recursive int, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withjoin map[string]int, searchthreads int, searchtimeout int) ([]KeysInfo, error) {

	var key sync.Mutex

	var ikeys []KeysInfo
	var skeys []KeysInfo

	var sdcheck bool = false

	bprefix := []byte("b:" + prefix)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	dirpath = filepath.Clean(dirpath)
	// url = strings.TrimSuffix(url, "/")

	paths, err := RTree(dirpath, withjoin, recursive)
	if err != nil {
		return ikeys, err
	}

	pkeys := make([]string, 0, len(paths))
	for pk := range paths {
		pkeys = append(pkeys, pk)
	}

	sort.Strings(pkeys)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(searchtimeout)*time.Second)
	defer cancel()

	if offset > 0 {
		searchthreads = 1
	}

	qwg, ctx := waitgroup.NewErrorGroup(ctx, searchthreads)

Main:

	for _, idirname := range pkeys {

		select {
		case <-ctx.Done():
			err = ctx.Err()
			break Main
		default:
		}

		dirname := idirname
		dcrc := paths[dirname]

		qwg.Add(func() error {

			qoffset := offset

			cl := 1

			vdirname := strings.TrimPrefix(dirname, base) + "/"

			nbucket := strconv.FormatUint(dcrc, 16)

			nerr := ndb.View(func(tx *nutsdb.Tx) error {

				var err error

				var entries nutsdb.Entries

				var off int

				switch {
				case expression != "(.+)" || (prefix != "" && expression != "(.+)"):
					entries, off, err = tx.PrefixSearchScan(nbucket, bprefix, expression, qoffset, limit)
				default:
					entries, off, err = tx.PrefixScan(nbucket, bprefix, qoffset, limit)
				}

				if entries == nil {

					key.Lock()
					offset = qoffset - off
					key.Unlock()

					return nil

				}

				if err != nil {
					return err
				}

				err = nil

				key.Lock()
				offset = offset - off
				key.Unlock()

			SubMain:

				for _, entry := range entries {

					select {
					case <-ctx.Done():
						err = ctx.Err()
						break SubMain
					default:
					}

					if cl > limit && limit > 0 {
						break
					}

					var ik KeysInfo
					var ev RawKeysData

					kname := strings.TrimPrefix(string(entry.Key), "b:")

					err = binary.Read(bytes.NewReader(entry.Value), Endian, &ev)
					if err != nil {
						return err
					}

					if sdcheck {

						switch {
						case ev.Size < minsize && minsize > 0:
							continue
						case ev.Size > maxsize && maxsize > 0:
							continue
						case ev.Date < minstmp && minstmp > 0:
							continue
						case ev.Date > maxstmp && maxstmp > 0:
							continue
						}

					}

					kname = strings.TrimPrefix(vdirname+kname, "/")

					if withurl {
						kname = url + "/" + kname
					}

					ik.Key = kname
					ik.Type = 1
					ik.Size = ev.Size
					ik.Date = ev.Date

					key.Lock()
					ikeys = append(ikeys, ik)
					key.Unlock()

					if stopfirst == 1 {
						break
					}

					cl++

				}

				if err != nil {
					return err
				}

				return nil

			})

			if nerr != nil {
				cancel()
				return nerr
			}

			return nil

		})

	}

	if err != nil {
		return ikeys, err
	}

	if werr := qwg.Wait(); werr != nil {
		return ikeys, werr
	}

	switch {
	case msort == 0:
		sort.Sort(KeysInfoListAsc(ikeys))
	case msort == 1:
		sort.Sort(KeysInfoListDsc(ikeys))
	}

	if limit > 0 || stopfirst == 1 {

		cl := 1

		for _, ssk := range ikeys {

			if cl > limit && limit > 0 {
				break
			}

			skeys = append(skeys, ssk)

			if stopfirst == 1 {
				break
			}

			cl++

		}

		return skeys, err

	}

	return ikeys, err

}

// DBKeysSearch : search key names/names with values through requested directory
func DBKeysSearch(filemode os.FileMode, timeout time.Duration, opentries int, freelist string, ndb *nutsdb.DB, base string, dirpath string, msort uint8, offset int, limit int, prefix string, expression string, recursive int, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withjoin map[string]int, withvalue bool, vmaxsize int64, searchthreads int, searchtimeout int) ([]KeysSearch, error) {

	var key sync.Mutex

	var ikeys []KeysSearch
	var skeys []KeysSearch

	imaxsize := uint64(vmaxsize)

	var sdcheck bool = false

	bprefix := []byte("b:" + prefix)

	if minsize > 0 || maxsize > 0 || minstmp > 0 || maxstmp > 0 {
		sdcheck = true
	}

	dirpath = filepath.Clean(dirpath)
	// url = strings.TrimSuffix(url, "/")

	paths, err := RTree(dirpath, withjoin, recursive)
	if err != nil {
		return ikeys, err
	}

	pkeys := make([]string, 0, len(paths))
	for pk := range paths {
		pkeys = append(pkeys, pk)
	}

	sort.Strings(pkeys)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(searchtimeout)*time.Second)
	defer cancel()

	if offset > 0 {
		searchthreads = 1
	}

	qwg, ctx := waitgroup.NewErrorGroup(ctx, searchthreads)

Main:

	for _, idirname := range pkeys {

		select {
		case <-ctx.Done():
			err = ctx.Err()
			break Main
		default:
		}

		dirname := idirname
		dcrc := paths[dirname]

		qwg.Add(func() error {

			qoffset := offset

			cl := 1

			pbdbname := dirname + "/" + filepath.Base(dirname)

			vdirname := strings.TrimPrefix(dirname, base) + "/"

			nbucket := strconv.FormatUint(dcrc, 16)

			nerr := ndb.View(func(tx *nutsdb.Tx) error {

				var err error

				var entries nutsdb.Entries

				var off int

				switch {
				case expression != "(.+)" || (prefix != "" && expression != "(.+)"):
					entries, off, err = tx.PrefixSearchScan(nbucket, bprefix, expression, qoffset, limit)
				default:
					entries, off, err = tx.PrefixScan(nbucket, bprefix, qoffset, limit)
				}

				if entries == nil {

					key.Lock()
					offset = qoffset - off
					key.Unlock()

					return nil

				}

				if err != nil {
					return err
				}

				err = nil

				key.Lock()
				offset = offset - off
				key.Unlock()

			SubMain:

				for _, entry := range entries {

					select {
					case <-ctx.Done():
						err = ctx.Err()
						break SubMain
					default:
					}

					if cl > limit && limit > 0 {
						break
					}

					var ik KeysSearch
					var ev RawKeysData

					kname := strings.TrimPrefix(string(entry.Key), "b:")

					err = binary.Read(bytes.NewReader(entry.Value), Endian, &ev)
					if err != nil {
						return err
					}

					if sdcheck {

						switch {
						case ev.Size < minsize && minsize > 0:
							continue
						case ev.Size > maxsize && maxsize > 0:
							continue
						case ev.Date < minstmp && minstmp > 0:
							continue
						case ev.Date > maxstmp && maxstmp > 0:
							continue
						}

					}

					if withvalue && ev.Size <= imaxsize {

						dbname := pbdbname + ".bolt"
						bucket := fmt.Sprintf("wzd%d", ev.Buck)

						if ev.Prnt > 0 {
							dbname = pbdbname + "_" + fmt.Sprintf("%08d%s", ev.Prnt, ".bolt")
						}

						if !FileExists(dbname) {
							continue
						}

						db, err := BoltOpenRead(dbname, filemode, timeout, opentries, freelist)
						if err != nil {
							return err
						}

						value, err := DBGetVal(db, bucket, []byte(kname))
						if err != nil {
							db.Close()
							return err
						}

						if value != nil {
							ik.Value = hex.EncodeToString(value)
						}

						db.Close()

					}

					kname = strings.TrimPrefix(vdirname+kname, "/")

					if withurl {
						kname = url + "/" + kname
					}

					ik.Key = kname
					ik.Type = 1
					ik.Size = ev.Size
					ik.Date = ev.Date

					key.Lock()
					ikeys = append(ikeys, ik)
					key.Unlock()

					if stopfirst == 1 {
						break
					}

					cl++

				}

				if err != nil {
					return err
				}

				return nil

			})

			if nerr != nil {
				cancel()
				return nerr
			}

			return nil

		})

	}

	if err != nil {
		return ikeys, err
	}

	if werr := qwg.Wait(); werr != nil {
		return ikeys, werr
	}

	switch {
	case msort == 0:
		sort.Sort(KeysSearchListAsc(ikeys))
	case msort == 1:
		sort.Sort(KeysSearchListDsc(ikeys))
	}

	if limit > 0 || stopfirst == 1 {

		cl := 1

		for _, ssk := range ikeys {

			if cl > limit && limit > 0 {
				break
			}

			skeys = append(skeys, ssk)

			if stopfirst == 1 {
				break
			}

			cl++

		}

		return skeys, err

	}

	return ikeys, err

}

// AllKeys : search summary file and key names through requested directory
func AllKeys(ndb *nutsdb.DB, base string, dirpath string, msort uint8, offset int, limit int, prefix string, expression string, recursive int, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withjoin map[string]int, searchthreads int, searchtimeout int) ([]Keys, error) {

	var ikeys []Keys

	fskeys, co, cl, err := FileKeys(ndb, base, dirpath, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, url, withjoin, searchthreads, searchtimeout)
	if err != nil {
		return ikeys, err
	}

	if (len(fskeys)) >= 1 && stopfirst == 1 {
		return fskeys, nil
	}

	if cl > limit && limit > 0 {
		return fskeys, nil
	}

	if limit > 0 {
		limit = limit - cl + 1
	}

	offset = co

	dbkeys, err := DBKeys(ndb, base, dirpath, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, url, withjoin, searchthreads, searchtimeout)
	if err != nil {
		return ikeys, err
	}

	ikeys = append(ikeys, append(fskeys, dbkeys...)...)

	return ikeys, nil

}

// AllKeysInfo : search summary file and key names with info through requested directory
func AllKeysInfo(ndb *nutsdb.DB, base string, dirpath string, msort uint8, offset int, limit int, prefix string, expression string, recursive int, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withjoin map[string]int, searchthreads int, searchtimeout int) ([]KeysInfo, error) {

	var ikeys []KeysInfo

	fskeys, co, cl, err := FileKeysInfo(ndb, base, dirpath, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, url, withjoin, searchthreads, searchtimeout)
	if err != nil {
		return ikeys, err
	}

	if (len(fskeys)) >= 1 && stopfirst == 1 {
		return fskeys, nil
	}

	if cl > limit && limit > 0 {
		return fskeys, nil
	}

	if limit > 0 {
		limit = limit - cl + 1
	}

	offset = co

	dbkeys, err := DBKeysInfo(ndb, base, dirpath, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, url, withjoin, searchthreads, searchtimeout)
	if err != nil {
		return ikeys, err
	}

	ikeys = append(ikeys, append(fskeys, dbkeys...)...)

	return ikeys, nil

}

// AllKeysSearch : search summary file and key names/names with values through requested directory
func AllKeysSearch(filemode os.FileMode, timeout time.Duration, opentries int, freelist string, ndb *nutsdb.DB, base string, dirpath string, msort uint8, offset int, limit int, prefix string, expression string, recursive int, stopfirst uint8, minsize uint64, maxsize uint64, minstmp uint64, maxstmp uint64, withurl bool, url string, withjoin map[string]int, withvalue bool, vmaxsize int64, searchthreads int, searchtimeout int) ([]KeysSearch, error) {

	var ikeys []KeysSearch

	fskeys, co, cl, err := FileKeysSearch(ndb, base, dirpath, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, url, withjoin, withvalue, vmaxsize, searchthreads, searchtimeout)
	if err != nil {
		return ikeys, err
	}

	if (len(fskeys)) >= 1 && stopfirst == 1 {
		return fskeys, nil
	}

	if cl > limit && limit > 0 {
		return fskeys, nil
	}

	if limit > 0 {
		limit = limit - cl + 1
	}

	offset = co

	dbkeys, err := DBKeysSearch(filemode, timeout, opentries, freelist, ndb, base, dirpath, msort, offset, limit, prefix, expression, recursive, stopfirst, minsize, maxsize, minstmp, maxstmp, withurl, url, withjoin, withvalue, vmaxsize, searchthreads, searchtimeout)
	if err != nil {
		return ikeys, err
	}

	ikeys = append(ikeys, append(fskeys, dbkeys...)...)

	return ikeys, nil

}

// RTree : search directories names through requested directory with maximum available recursion level = 3
func RTree(dirpath string, withjoin map[string]int, recursive int) (paths map[string]uint64, err error) {

	paths = make(map[string]uint64)

	if recursive > 3 || recursive < 0 {
		recursive = 3
	}

	switch {

	case len(withjoin) == 0 && recursive == 0:
		paths[dirpath] = crc64.Checksum([]byte(dirpath), ctbl64)
		return paths, nil
	case len(withjoin) == 0:
		withjoin[dirpath] = recursive
	}

	radix.RLock()
	root := tree.Root()

	for edir, erec := range withjoin {

		spc := strings.Count(edir, "/")

		recursive = erec

		walk := func(bdir []byte, dcrc interface{}) bool {

			fpc := bytes.Count(bdir, bslash) - recursive

			if spc >= fpc {
				paths[string(bdir)] = dcrc.(uint64)
			}

			return false

		}

		root.WalkPrefix([]byte(edir), walk)

	}
	radix.RUnlock()

	return paths, nil

}
