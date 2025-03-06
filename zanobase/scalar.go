package zanobase

import (
	"encoding/hex"
	"encoding/json"
	"io"

	"filippo.io/edwards25519"
)

type Scalar struct {
	*edwards25519.Scalar
}

func (s *Scalar) MarshalJSON() ([]byte, error) {
	if s.Scalar == nil {
		return []byte("null"), nil
	}
	return json.Marshal(hex.EncodeToString(s.Scalar.Bytes()))
}

func (s *Scalar) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(s.Scalar.Bytes())
	return int64(n), err
}

func (s *Scalar) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 32)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return int64(n), err
	}
	if s.Scalar == nil {
		s.Scalar = new(edwards25519.Scalar)
	}
	_, err = s.Scalar.SetCanonicalBytes(buf)
	return int64(n), err
}
