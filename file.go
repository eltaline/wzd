package main

import (
	"io"
	"os"
	"path/filepath"
)

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

// IsEmptyDir : check on empty directory
func IsEmptyDir(directory string) (bool, error) {

	dir, err := os.Open(directory)
	if err != nil {
		return false, err
	}
	defer dir.Close()

	_, err = dir.Readdir(1)
	if err != nil {

		if err == io.EOF {
			return true, nil
		}

		return false, err

	}

	return false, nil

}

// RemoveFile : remove requested file and/or empty dir
func RemoveFile(filename string, directory string, deldir bool) error {

	err := os.Remove(filename)
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

// RemoveFileDB : remove requested BoltDB file and/or empty dir
func RemoveFileDB(filename string, directory string, deldir bool) error {

	err := os.Remove(filename)
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

// RemoveSegment : remove NutsDB segment file if empty
func RemoveSegment(filename string) error {

	err := os.Remove(filename)
	if err != nil {
		return err
	}

	return nil

}
