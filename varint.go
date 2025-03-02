package zanolib

import (
	"errors"
	"io"
)

type Varint uint64

func (v Varint) Bytes() []byte {
	return VarintAppendUint64(nil, uint64(v))
}

func (v *Varint) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	n, err := VarintReadUint64(rc)
	if err != nil {
		return rc.error(err)
	}
	*v = Varint(n)
	return rc.ret()
}

func VarintPackedSize(v uint64) int {
	switch {
	case v <= 0x7f:
		return 1
	case v <= 0x3fff:
		return 2
	case v <= 0x1f_ffff:
		return 3
	case v <= 0xfff_ffff:
		return 4
	case v <= 0x7_ffff_ffff:
		return 5
	case v <= 0x3ff_ffff_ffff:
		return 6
	case v <= 0x1_ffff_ffff_ffff:
		return 7
	default:
		return 8
	}
}

func VarintAppendUint64(buf []byte, v uint64) []byte {
	for v > 0x80 {
		buf = append(buf, byte(v&0x7f)|0x80)
		v >>= 7
	}
	buf = append(buf, byte(v))
	return buf
}

func VarintTakeUint64(buf []byte) ([]byte, uint64, error) {
	var v uint64
	var offt int
	for len(buf) > 0 && buf[0]&0x80 == 0x80 {
		v |= (uint64(buf[0]) & 0x7f) << offt
		offt += 7
		buf = buf[1:]
	}
	if len(buf) == 0 {
		return buf, v, errors.New("buffer underrun while decoding varint")
	}
	v |= uint64(buf[0]) << offt
	return buf[1:], v, nil
}

func VarintReadUint64(r io.ByteReader) (uint64, error) {
	var v uint64
	var offt int
	for {
		n, err := r.ReadByte()
		if err != nil {
			return v, notEOF(err)
		}
		v |= (uint64(n) & 0x7f) << offt
		offt += 7
		if n&0x80 == 0 {
			return v, nil
		}
	}
}

func notEOF(e error) error {
	if errors.Is(e, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return e
}
