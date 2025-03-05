package zanobase

import (
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ModChain/edwards25519"
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

func (v Value256) B32() [32]byte {
	return [32]byte(v)
}

func (v *Value256) PB32() *[32]byte {
	return (*[32]byte)(v)
}

func (v *Value256) ToExtended() *edwards25519.ExtendedGroupElement {
	var ex edwards25519.ExtendedGroupElement
	if !ex.FromBytes(v.PB32()) {
		return nil
	}
	return &ex
}
