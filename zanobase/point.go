package zanobase

import (
	"encoding/hex"
	"encoding/json"
	"io"

	"filippo.io/edwards25519"
)

type Point struct {
	*edwards25519.Point
}

func (p *Point) MarshalJSON() ([]byte, error) {
	if p.Point == nil {
		return []byte("null"), nil
	}
	return json.Marshal(hex.EncodeToString(p.Point.Bytes()))
}

func (p *Point) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(p.Point.Bytes())
	return int64(n), err
}

func (p *Point) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 32)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return int64(n), err
	}
	if p.Point == nil {
		p.Point = new(edwards25519.Point)
	}
	_, err = p.Point.SetBytes(buf)
	return int64(n), err
}
