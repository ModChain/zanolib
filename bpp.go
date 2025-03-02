package zanolib

import "io"

type BPPSignature struct {
	Lv    [][32]byte // std::vector<public_key> size = ceil( log_2(m * n) )
	Rv    [][32]byte // std::vector<public_key>
	A0    [32]byte   // public_key
	A     [32]byte   // public_key
	B     [32]byte   // public_key
	R     [32]byte   // scalar_t
	S     [32]byte   // scalar_t
	Delta [32]byte   // scalar_t
}

func (s *BPPSignature) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	var err error
	s.Lv, err = rc.readVec32()
	if err != nil {
		return rc.error(err)
	}
	s.Rv, err = rc.readVec32()
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(s.A0[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(s.A[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(s.B[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(s.R[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(s.S[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(s.Delta[:])
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}
