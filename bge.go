package zanolib

import (
	"fmt"
	"io"
)

type BGEProof struct {
	A  [32]byte   // public_key, premultiplied by 1/8
	B  [32]byte   // public_key, premultiplied by 1/8
	Pk [][32]byte // premultiplied by 1/8, size = m
	F  [][32]byte // scalar_vec_t size = m * (n - 1)
	Y  [32]byte   // scalar_t
	Z  [32]byte   // scalar_t
}

func (bge *BGEProof) ReadFrom(r io.Reader) (int64, error) {
	// BGE_proof_s
	rc := rc(r)
	err := rc.readFull(bge.A[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(bge.B[:])
	if err != nil {
		return rc.error(err)
	}
	cnt, err := VarintReadUint64(rc)
	if err != nil {
		return rc.error(err)
	}
	if cnt > 128 {
		return rc.error(fmt.Errorf("in BGEProof, n too large, %d > 128", cnt))
	}
	bge.Pk = make([][32]byte, cnt)
	for n := range bge.Pk {
		err = rc.readFull(bge.Pk[n][:])
		if err != nil {
			return rc.error(err)
		}
	}
	cnt, err = VarintReadUint64(rc)
	if err != nil {
		return rc.error(err)
	}
	if cnt > 128 {
		return rc.error(fmt.Errorf("in BGEProof, m*(n-1) too large, %d > 128", cnt))
	}
	bge.F = make([][32]byte, cnt)
	for n := range bge.F {
		err = rc.readFull(bge.F[n][:])
		if err != nil {
			return rc.error(err)
		}
	}
	err = rc.readFull(bge.Y[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(bge.Z[:])
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}
