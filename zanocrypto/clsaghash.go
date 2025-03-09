package zanocrypto

import (
	"hash"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

type clsagHash struct {
	h hash.Hash
}

type byter interface {
	Bytes() []byte
}

func newClsagHash() *clsagHash {
	return &clsagHash{h: sha3.NewLegacyKeccak256()}
}

func (c *clsagHash) addBytes(b []byte) {
	if len(b) != 32 {
		panic("addbytes expect 32 bytes")
	}
	c.h.Write(b)
}

func (c *clsagHash) addBytesModL(b []byte) {
	if len(b) != 32 {
		panic("addbytes expect 32 bytes")
	}
	var wide [64]byte
	copy(wide[:], b)
	sc, _ := new(edwards25519.Scalar).SetUniformBytes(wide[:])
	c.addScalarBytes(sc)
}

func (c *clsagHash) addPointBytes(p *edwards25519.Point) {
	c.h.Write(p.Bytes())
}

func (c *clsagHash) addScalarBytes(s *edwards25519.Scalar) {
	c.h.Write(s.Bytes())
}

func (c *clsagHash) add(v ...byter) {
	for _, s := range v {
		c.h.Write(s.Bytes())
	}
}

func (c *clsagHash) calcHash() *edwards25519.Scalar {
	res := c.h.Sum(nil)
	c.h.Reset()
	var buf64 [64]byte
	copy(buf64[:], res)
	pt, _ := new(edwards25519.Scalar).SetUniformBytes(buf64[:])
	return pt
}

// calcHashKeep is the same as calcHash but does not reset the state
func (c *clsagHash) calcHashKeep() *edwards25519.Scalar {
	res := c.h.Sum(nil)
	var buf64 [64]byte
	copy(buf64[:], res)
	pt, _ := new(edwards25519.Scalar).SetUniformBytes(buf64[:])
	return pt
}

func (c *clsagHash) calcRawHash() []byte {
	res := c.h.Sum(nil)
	c.h.Reset()
	return res
}

func bter[T []S, S byter](v T) []byter {
	res := make([]byter, len(v))
	for n, a := range v {
		res[n] = a
	}
	return res
}
