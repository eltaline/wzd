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
	"mime"
	"net/http"
	"path/filepath"
)

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
