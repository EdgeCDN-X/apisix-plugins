package main

import "fmt"

//go:wasmimport env proxy_set_property
func proxySetProperty(path *byte, pathSize int32, value *byte, valueSize int32) uint32

func clearQueryArgs() error {
	// The SDK rejects empty values, but Nginx needs one to clear $args.
	path := []byte("args")
	var empty byte
	if status := proxySetProperty(&path[0], int32(len(path)), &empty, 0); status != 0 {
		return fmt.Errorf("clear query arguments: proxy_set_property returned status %d", status)
	}
	return nil
}
