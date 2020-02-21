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
	"fmt"
	"os"
)

// Working helpers

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
