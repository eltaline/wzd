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
	"encoding/binary"
	"fmt"
	// "github.com/eltaline/machineid"
	"os"
	"os/user"
	"strconv"
	"unsafe"
)

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
/*func MachineID() {

	var err error

	machid, err = machineid.ID()
	if err != nil {
		machid = "nomachineid"
	}

}*/
