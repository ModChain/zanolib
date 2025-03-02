package zanolib

import (
	"bufio"
	"io"
)

type ByteAndReadReader interface {
	io.ByteReader
	io.Reader
}

type readCounter struct {
	parent ByteAndReadReader
	cnt    int64
	err    error
}

func (rc *readCounter) ReadByte() (byte, error) {
	res, err := rc.parent.ReadByte()
	if err == nil {
		rc.cnt += 1
	} else {
		rc.err = err
	}
	return res, err
}

func (rc *readCounter) Read(p []byte) (n int, err error) {
	res, err := rc.parent.Read(p)
	rc.cnt += int64(res)
	if err != nil {
		rc.err = err
	}
	return res, err
}

func (rc *readCounter) ret() (int64, error) {
	return rc.cnt, rc.err
}

func (rc *readCounter) error(err error) (int64, error) {
	return rc.cnt, err
}

func rc(r io.Reader) *readCounter {
	switch o := r.(type) {
	case *readCounter:
		return &readCounter{parent: o}
	case ByteAndReadReader:
		return &readCounter{parent: o}
	case io.Reader:
		buf := bufio.NewReader(o)
		return &readCounter{parent: buf}
	default:
		panic("object cannot be handled as ByteAndReadReader")
	}
}
