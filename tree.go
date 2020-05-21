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
	"context"
	"fmt"
	"github.com/eltaline/cwalk"
	"github.com/pieterclaerhout/go-waitgroup"
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

	qwait := make(chan bool)

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

			qdirname := dirname

			qwait <- true

			err := cwalk.Walk(qdirname, func(partpath string, ln os.FileInfo, err error) error {

				if err != nil {
					return err
				}

				if ln.IsDir() {

					fullpath := []byte(filepath.Clean(qdirname + "/" + partpath))

					radix.Lock()
					tree, _, _ = tree.Insert(fullpath, crc64.Checksum(fullpath, ctbl64))
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

		<-qwait

	}

	werr := qwg.Wait()

	if err != nil || werr != nil {
		fmt.Printf("Tree initialization error | %v | %v\n", err, werr)
		os.Exit(1)
	}

}
