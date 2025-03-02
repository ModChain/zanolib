package zanolib

import (
	"encoding/json"
	"fmt"
	"io"
)

type Payload struct {
	Tag   uint8
	Value any // any type stored as a boost::variant
}

type tagDefinition struct {
	read func(p *Payload, rc *readCounter) (int64, error)
	name string
}

var variantTags = map[uint8]*tagDefinition{
	0:  {payloadOf[*TxInGen], "gen"},
	11: {payloadOf[[]byte], "derivation_hint"},
	22: {payloadOf[Value256], "pub_key"},
	23: {payloadOf[uint16], "etc_tx_flags16"},
	24: {payloadOf[uint16], "derive_xor"},
	25: {payloadOf[*RefById], "ref_by_id"},
	26: {payloadOf[uint64], "uint64_t"},
	28: {payloadOf[uint32], "uint32_t"},
	37: {payloadOf[*TxInZcInput], "txin_zc_input"},
	38: {payloadOf[*TxOutZarcanium], "tx_out_zarcanum"},
	39: {payloadOf[*ZarcaniumTxDataV1], "zarcanum_tx_data_v1"},
	43: {payloadOf[*ZCSig], "ZC_sig"},
	46: {payloadOf[*ZCAssetSurjectionProof], "zc_asset_surjection_proof"},
	47: {payloadOf[*ZCOutsRangeProof], "zc_outs_range_proof"},
	48: {payloadOf[*ZCBalanceProof], "zc_balance_proof"},
}

type marshalledPayload struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

func (p *Payload) MarshalJSON() ([]byte, error) {
	obj := &marshalledPayload{
		Value: p.Value,
	}
	if v, ok := variantTags[p.Tag]; ok {
		obj.Type = v.name
	} else {
		obj.Type = fmt.Sprintf("unknown#%d", p.Tag)
	}
	return json.Marshal(obj)
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

	p.Tag = b

	v, ok := variantTags[b]
	if !ok {
		return rc.error(fmt.Errorf("unsupported tag value: %d", b))
	}

	return v.read(p, rc)
}

func payloadOf[T any](p *Payload, rc *readCounter) (int64, error) {
	var val T
	err := Deserialize(rc, &val)
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
