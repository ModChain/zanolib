package zanolib

import (
	"encoding/binary"
	"io"
)

type TxInGen struct {
	Height uint64
}

func (txin *TxInGen) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	err := binary.Read(rc, binary.LittleEndian, &txin.Height)
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}

type TxInZcInput struct {
	// referring_input
	KeyOffsets []*Payload // std::vector<txout_ref_v>; typedef boost::variant<uint64_t, ref_by_id> txout_ref_v
	// txin_zc_input
	KeyImage   [32]byte   // crypto::key_image = ec_point
	EtcDetails []*Payload // std::vector<txin_etc_details_v> = std::vector<boost::variant<signed_parts, extra_attachment_info>>
}

func (txin *TxInZcInput) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	var err error
	txin.KeyOffsets, err = readPayloads(rc)
	if err != nil {
		return rc.error(err)
	}
	_, err = io.ReadFull(rc, txin.KeyImage[:])
	if err != nil {
		return rc.error(err)
	}
	txin.EtcDetails, err = readPayloads(rc)
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}
