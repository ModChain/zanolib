package zanolib

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"runtime"
)

type ByteAndReadReader interface {
	io.ByteReader
	io.Reader
}

type readCounter struct {
	parent ByteAndReadReader
	ctx    string
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
	return rc.cnt, fmt.Errorf("in %s: %w", rc.ctx, err)
}

func (rc *readCounter) into(o io.ReaderFrom) error {
	_, err := o.ReadFrom(rc)
	return err
}

func (rc *readCounter) readFull(buf []byte) error {
	_, err := io.ReadFull(rc, buf)
	return err
}

func (rc *readCounter) readVarBytes() ([]byte, error) {
	ln, err := VarintReadUint64(rc)
	if err != nil {
		return nil, err
	}
	if ln > 4096 {
		return nil, fmt.Errorf("read var bytes: array too large: %d > 4096", ln)
	}
	buf := make([]byte, ln)
	_, err = io.ReadFull(rc, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (rc *readCounter) readVec32() ([][32]byte, error) {
	ln, err := VarintReadUint64(rc)
	if err != nil {
		return nil, err
	}
	if ln > 128 {
		return nil, fmt.Errorf("read vec32 too large: %d > 128", ln)
	}
	res := make([][32]byte, ln)
	for n := range res {
		err = rc.readFull(res[n][:])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (rc *readCounter) magic(vs ...any) (int64, error) {
	var err error
	for n, v := range vs {
		switch o := v.(type) {
		case *bool, *uint64:
			err = binary.Read(rc, binary.LittleEndian, o)
			if err != nil {
				return rc.error(fmt.Errorf("in argument %d: %w", n, err))
			}
		case *[32]byte:
			err = rc.readFull((*o)[:])
			if err != nil {
				return rc.error(fmt.Errorf("in argument %d: %w", n, err))
			}
		case *[][32]byte:
			*o, err = rc.readVec32()
			if err != nil {
				return rc.error(fmt.Errorf("in argument %d: %w", n, err))
			}
		case *[]*Payload:
			*o, err = readPayloads(rc)
			if err != nil {
				return rc.error(fmt.Errorf("in argument %d: %w", n, err))
			}
		case io.ReaderFrom:
			err = rc.into(o)
			if err != nil {
				return rc.error(fmt.Errorf("in argument %d: %w", n, err))
			}
		default:
			return rc.error(fmt.Errorf("unsupported type for reader magic: %T", v))
		}
	}
	return rc.ret()
}

func rc(r io.Reader) *readCounter {
	// func Caller(skip int) (pc uintptr, file string, line int, ok bool)
	pc, fn, ln, ok := runtime.Caller(1)
	ctx := "unknown"
	if ok {
		f := runtime.FuncForPC(pc)
		ctx = fmt.Sprintf("%s at %s:%d", f.Name(), path.Base(fn), ln)
	}
	switch o := r.(type) {
	case *readCounter:
		return &readCounter{parent: o, ctx: ctx}
	case ByteAndReadReader:
		return &readCounter{parent: o, ctx: ctx}
	case io.Reader:
		buf := bufio.NewReader(o)
		return &readCounter{parent: buf, ctx: ctx}
	default:
		panic("object cannot be handled as ByteAndReadReader")
	}
}
