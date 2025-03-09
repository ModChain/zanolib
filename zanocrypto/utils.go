package zanocrypto

import (
	"filippo.io/edwards25519"
	"github.com/ModChain/zanolib/zanobase"
)

func load3(in []byte) int64 {
	return int64(in[0]) | (int64(in[1]) << 8) | (int64(in[2]) << 16)
}

func load4(in []byte) int64 {
	return int64(in[0]) | (int64(in[1]) << 8) | (int64(in[2]) << 16) | (int64(in[3]) << 24)
}

func addPScalar(v **edwards25519.Scalar, a *edwards25519.Scalar) {
	if (*v) == nil {
		(*v) = new(edwards25519.Scalar).Set(a)
		return
	}
	(*v) = new(edwards25519.Scalar).Add((*v), a)
}

func addRefScalar(v **zanobase.Scalar, a *edwards25519.Scalar) {
	if (*v) == nil {
		(*v) = &zanobase.Scalar{new(edwards25519.Scalar).Set(a)}
		return
	}
	(*v).Scalar = new(edwards25519.Scalar).Add((*v).Scalar, a)
}

func addRefPoint(v **zanobase.Point, a *edwards25519.Point) {
	if (*v) == nil {
		(*v) = &zanobase.Point{new(edwards25519.Point).Set(a)}
		return
	}
	(*v).Point = new(edwards25519.Point).Add((*v).Point, a)
}
