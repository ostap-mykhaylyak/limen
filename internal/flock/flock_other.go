//go:build !unix

package flock

// Lock is a no-op where flock does not exist. limen runs on Linux;
// this only lets the package build and test on a development machine.
func Lock(string) (func(), error) { return func() {}, nil }
