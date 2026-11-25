//go:build !wasip1

package main

import "errors"

func clearQueryArgs() error {
	return errors.New("clearing query arguments requires a WASI host")
}
