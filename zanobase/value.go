package zanobase

import (
	"encoding/hex"
	"encoding/json"
	"io"

	"filippo.io/edwards25519"
)

type Value256 [32]byte

func (v *Value256) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.ReadFull(r, v[:])
	return int64(n), err
}

func (v Value256) Bytes() []byte {
	return v[:]
}

func (v Value256) String() string {
	return hex.EncodeToString(v[:])
}

func (v Value256) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

func (v Value256) IsZero() bool {
	var t byte
	for _, b := range v {
		t |= b
	}
	return t == 0
}

func (v Value256) B32() [32]byte {
	return [32]byte(v)
}

func (v *Value256) PB32() *[32]byte {
	return (*[32]byte)(v)
}

func (v *Value256) ToPoint() *edwards25519.Point {
	p, err := new(edwards25519.Point).SetBytes(v[:])
	if err != nil {
		return nil
	}
	return p
}
