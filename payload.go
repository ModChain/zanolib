package zanolib

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

type Payload struct {
	Tag   uint8
	Value any // any type stored as a boost::variant
}

type tagDefinition struct {
	read func(p *Payload, rc *readCounter) (int64, error)
	new  func() any
	name string
}

var (
	variantTags   = make(map[uint8]*tagDefinition)
	tagNameLookup = make(map[string]uint8)
	tagTypeLookup = make(map[reflect.Type]uint8)
)

func defTag[T any](tag uint8, name string) {
	variantTags[tag] = &tagDefinition{
		read: payloadOf[T],
		name: name,
	}
	tagNameLookup[name] = tag

	t := reflect.TypeFor[T]()
	tagTypeLookup[t] = tag
}

func init() {
	defTag[*TxInGen](0, "gen")
	defTag[[]byte](11, "derivation_hint")
	defTag[Value256](22, "pub_key")
	defTag[uint16](23, "etc_tx_flags16")
	defTag[uint16](24, "derive_xor")
	defTag[*RefById](25, "ref_by_id")
	defTag[uint64](26, "uint64_t")
	defTag[uint32](28, "uint32_t")
	defTag[*TxInZcInput](37, "txin_zc_input")
	defTag[*TxOutZarcanium](38, "tx_out_zarcanum")
	defTag[*ZarcaniumTxDataV1](39, "zarcanum_tx_data_v1")
	defTag[*ZCSig](43, "ZC_sig")
	defTag[*ZCAssetSurjectionProof](46, "zc_asset_surjection_proof")
	defTag[*ZCOutsRangeProof](47, "zc_outs_range_proof")
	defTag[*ZCBalanceProof](48, "zc_balance_proof")
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

func payloadFor[T any](obj T) *Payload {
	t := reflect.TypeFor[T]()
	tag, ok := tagTypeLookup[t]
	if !ok {
		tag = 0xff
	}
	return &Payload{Tag: tag, Value: obj}
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

func payloadAs[T any](p *Payload) T {
	return p.Value.(T)
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
