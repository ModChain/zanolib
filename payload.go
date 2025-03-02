package zanolib

import (
	"encoding/binary"
	"fmt"
	"io"
)

type Payload struct {
	Value any // any type stored as a boost::variant
}

func readPayloads(rc ByteAndReadReader) ([]*Payload, error) {
	return arrayOf[Payload](rc)
}

func (p *Payload) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)
	b, err := rc.ReadByte()
	if err != nil {
		return rc.error(err)
	}

	switch b {
	case 0: // txin_gen
		return payloadOf[TxInGen](p, rc)
	case 11:
		// tx_derivation_hint
		buf, err := rc.readVarBytes()
		if err != nil {
			return rc.error(err)
		}
		p.Value = buf
		return rc.ret()
	case 22:
		// public key
		buf := make([]byte, 32)
		_, err = io.ReadFull(rc, buf)
		if err != nil {
			return rc.error(err)
		}
		p.Value = buf
		return rc.ret()
	case 23:
		// etc_tx_flags16_t
		var val uint16
		err = binary.Read(rc, binary.LittleEndian, &val)
		if err != nil {
			return rc.error(err)
		}
		p.Value = val
		return rc.ret()
	case 25: // currency::ref_by_id: hash + 32bits n
		return payloadOf[RefById](p, rc)
	case 26: // uint64
		var val uint64
		err = binary.Read(rc, binary.LittleEndian, &val)
		if err != nil {
			return rc.error(err)
		}
		p.Value = val
		return rc.ret()
	case 37:
		return payloadOf[TxInZcInput](p, rc)
	case 38:
		return payloadOf[TxOutZarcanium](p, rc)
	case 39:
		return payloadOf[ZarcaniumTxDataV1](p, rc)
	case 43:
		return payloadOf[ZCSig](p, rc)
	case 46:
		return payloadOf[ZCAssetSurjectionProof](p, rc)
	case 47:
		return payloadOf[ZCOutsRangeProof](p, rc)
	case 48:
		return payloadOf[ZCBalanceProof](p, rc)
	default:
		return rc.error(fmt.Errorf("unsupported tag value: %d", b))
	}
}

func payloadOf[T any, PT interface {
	io.ReaderFrom
	*T
}](p *Payload, rc *readCounter) (int64, error) {
	var val PT = new(T)
	_, err := val.ReadFrom(rc)
	if err != nil {
		return rc.error(err)
	}
	p.Value = val
	return rc.ret()
}

func arrayOf[T any, PT interface {
	io.ReaderFrom
	*T
}](rc ByteAndReadReader) ([]*T, error) {
	cnt, err := VarintReadUint64(rc)
	if err != nil {
		return nil, err
	}
	if cnt > 128 {
		return nil, fmt.Errorf("while reading payload array: too many values %d > 128", cnt)
	}
	res := make([]*T, cnt)

	for n := range res {
		var val *T = new(T)
		_, err := PT(val).ReadFrom(rc)
		if err != nil {
			return nil, err
		}
		res[n] = val
	}
	return res, nil
}
