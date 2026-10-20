//go:build !cgo

package mailstrix

// nativeTrim is a no-op without cgo: there is no libyara heap to trim.
func nativeTrim() {}
