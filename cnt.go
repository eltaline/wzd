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
