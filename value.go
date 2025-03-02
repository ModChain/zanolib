package zanolib

import (
	"encoding/hex"
	"encoding/json"
	"io"
)

type Value256 [32]byte

func (v *Value256) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	err := rc.readFull(v[:])
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}

func (v Value256) String() string {
	return hex.EncodeToString(v[:])
}

func (v Value256) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}
