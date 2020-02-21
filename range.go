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
	"errors"
	"strconv"
	"strings"
)

// Ranges Helpers

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
