package zanolib

import (
	"fmt"
	"io"
)

type ZCSig struct {
	// ZC_sig
	PseudoOutAmountCommitment [32]byte // premultiplied by 1/8
	PseudoOutBlindedAssetId   [32]byte // premultiplied by 1/8
	// crypto::CLSAG_GGX_signature_serialized clsags_ggx
	GGX *CLSAG_Sig
}

func (s *ZCSig) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	err := rc.readFull(s.PseudoOutAmountCommitment[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(s.PseudoOutBlindedAssetId[:])
	if err != nil {
		return rc.error(err)
	}
	s.GGX = new(CLSAG_Sig)
	err = rc.into(s.GGX)
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}

type CLSAG_Sig struct {
	C   [32]byte   // scalar_t
	R_G [][32]byte // for G-components (layers 0, 1),    size = size of the ring
	R_X [][32]byte // for X-component  (layer 2),        size = size of the ring
	K1  [32]byte   // public_key auxiliary key image for layer 1 (G)
	K2  [32]byte   // public_key auxiliary key image for layer 2 (X)
}

func (s *CLSAG_Sig) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	err := rc.readFull(s.C[:])
	if err != nil {
		return rc.error(err)
	}
	cnt, err := VarintReadUint64(rc)
	if err != nil {
		return rc.error(err)
	}
	if cnt > 128 {
		return rc.error(fmt.Errorf("ring too large, %d > 128", cnt))
	}
	s.R_G = make([][32]byte, cnt)
	for n := range s.R_G {
		err = rc.readFull(s.R_G[n][:])
		if err != nil {
			return rc.error(err)
		}
	}
	cnt, err = VarintReadUint64(rc)
	if err != nil {
		return rc.error(err)
	}
	if cnt > 128 {
		return rc.error(fmt.Errorf("ring too large, %d > 128", cnt))
	}
	s.R_X = make([][32]byte, cnt)
	for n := range s.R_X {
		err = rc.readFull(s.R_X[n][:])
		if err != nil {
			return rc.error(err)
		}
	}
	err = rc.readFull(s.K1[:])
	if err != nil {
		return rc.error(err)
	}
	err = rc.readFull(s.K2[:])
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}
