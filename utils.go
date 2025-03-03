package zanolib

import "hash"

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func hsum(f func() hash.Hash, v []byte) []byte {
	h := f()
	h.Write(v)
	return h.Sum(nil)
}
