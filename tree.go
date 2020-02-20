package main

import (
	"context"
	"fmt"
	"github.com/eltaline/cwalk"
	"github.com/eltaline/go-waitgroup"
	"hash/crc64"
	"os"
	"path/filepath"
	"strings"
)

// TreeInit : Tree Database Initialization
func TreeInit() {

	var err error

	// Variables

	mdir := make(map[string]bool)

	for _, Server := range config.Server {

		root := filepath.Clean(Server.ROOT)
		uroot := root

		_, found := mdir[root]

		for {

			if uroot == "/" {
				break
			}

			for dirname := range mdir {

				if strings.HasPrefix(dirname, root+"/") {
					delete(mdir, dirname)
					found = false
				}

			}

			_, ufound := mdir[uroot]

			if ufound {
				found = true
				break
			}

			uroot = filepath.Dir(uroot)

		}

		if !found {
			mdir[root] = true
		}

	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	qwg, ctx := waitgroup.NewErrorGroup(ctx, searchinit)

Main:

	for idirname := range mdir {

		select {
		case <-ctx.Done():
			err = ctx.Err()
			break Main
		default:
		}

		dirname := idirname

		qwg.Add(func() error {

			err := cwalk.Walk(dirname, func(partpath string, ln os.FileInfo, err error) error {

				if err != nil {
					return err
				}

				if ln.IsDir() {

					fullpath := []byte(filepath.Clean(dirname + "/" + partpath))

					radix.Lock()
					tree, _, _ = tree.Insert(fullpath, crc64.Checksum([]byte(fullpath), ctbl64))
					radix.Unlock()

				}

				return nil

			})

			if err != nil {
				cancel()
				return err
			}

			return nil

		})

	}

	werr := qwg.Wait()

	if err != nil || werr != nil {
		fmt.Printf("Tree initialization error | %v | %v\n", err, werr)
		os.Exit(1)
	}

}
