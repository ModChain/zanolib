package zanobase

import (
	"encoding/hex"
	"encoding/json"
	"io"
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
