package zanolib

import (
	"encoding/binary"
	"fmt"
	"io"
)

type TxSourceOutputEntry struct {
	OutReference     []byte   // TxOutRef // either global output index or ref_by_id
	StealthAddress   [32]byte // crypto::public_key, a.k.a output's one-time public key
	ConcealingPoint  [32]byte // only for ZC outputs
	AmountCommitment [32]byte // only for ZC outputs
	BlindedAssetID   [32]byte // only for ZC outputs
}

type TxSource struct {
	Outputs                    []*TxSourceOutputEntry
	RealOutput                 uint64
	RealOutTxKey               [32]byte // crypto::public_key
	RealOutAmountBlindingMask  [32]byte // crypto::scalar_t
	RealOutAssetIdBlindingMask [32]byte // crypto::scalar_t
	RealOutInTxIndex           uint64   // size_t, index in transaction outputs vector
	Amount                     uint64
	TransferIndex              uint64
	MultisigId                 [32]byte // crypto::hash if txin_multisig: multisig output id
	MsSigsCount                uint64   // size_t
	MsKeysCount                uint64   // size_t
	SeparatelySignedTxComplete bool
	HtlcOrigin                 string // for htlc, specify origin. len = 1, content = "\x00" ?
}

func (src *TxSource) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	outputsCnt, err := VarintReadUint64(rc)
	if err != nil {
		return rc.ret()
	}
	src.Outputs = make([]*TxSourceOutputEntry, outputsCnt)
	for n := range src.Outputs {
		out := new(TxSourceOutputEntry)
		src.Outputs[n] = out
		_, err := out.ReadFrom(rc)
		if err != nil {
			return rc.error(err)
		}
	}
	err = binary.Read(rc, binary.LittleEndian, &src.RealOutput)
	if err != nil {
		return rc.error(err)
	}
	_, err = io.ReadFull(rc, src.RealOutTxKey[:])
	if err != nil {
		return rc.error(err)
	}
	_, err = io.ReadFull(rc, src.RealOutAmountBlindingMask[:])
	if err != nil {
		return rc.error(err)
	}
	_, err = io.ReadFull(rc, src.RealOutAssetIdBlindingMask[:])
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &src.RealOutInTxIndex)
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &src.Amount)
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &src.TransferIndex)
	if err != nil {
		return rc.error(err)
	}
	_, err = io.ReadFull(rc, src.MultisigId[:])
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &src.MsSigsCount)
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &src.MsKeysCount)
	if err != nil {
		return rc.error(err)
	}
	err = binary.Read(rc, binary.LittleEndian, &src.SeparatelySignedTxComplete)
	if err != nil {
		return rc.error(err)
	}
	strLn, err := VarintReadUint64(rc)
	if err != nil {
		return rc.error(err)
	}
	if strLn > 128 {
		return rc.error(fmt.Errorf("htlc_origin strlen too long: %d", strLn))
	}

	// assuming string is varint+bytes
	if strLn > 0 {
		buf := make([]byte, strLn)
		_, err = io.ReadFull(rc, buf)
		if err != nil {
			return rc.error(err)
		}
		src.HtlcOrigin = string(buf)
	}

	return rc.ret()
}

func (out *TxSourceOutputEntry) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	// first byte should be 26 (uint64) or 25 (currency::ref_by_id)
	outRefType, err := VarintReadUint64(rc)
	if err != nil {
		return rc.ret()
	}
	switch outRefType {
	case 25: // currency::ref_by_id: hash + 32bits n
		out.OutReference = make([]byte, 32+4)
		_, err = io.ReadFull(rc, out.OutReference)
		if err != nil {
			return rc.ret()
		}
	case 26: // uint64
		out.OutReference = make([]byte, 8)
		_, err = io.ReadFull(rc, out.OutReference)
		if err != nil {
			return rc.ret()
		}
	default:
		return rc.error(fmt.Errorf("unsupported tag %d in tx_source_output_entry", outRefType))
	}
	_, err = io.ReadFull(rc, out.StealthAddress[:])
	if err != nil {
		return rc.ret()
	}
	_, err = io.ReadFull(rc, out.ConcealingPoint[:])
	if err != nil {
		return rc.ret()
	}
	_, err = io.ReadFull(rc, out.AmountCommitment[:])
	if err != nil {
		return rc.ret()
	}
	_, err = io.ReadFull(rc, out.BlindedAssetID[:])
	if err != nil {
		return rc.ret()
	}
	return rc.ret()
}
