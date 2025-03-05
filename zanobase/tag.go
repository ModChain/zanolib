package zanobase

import "reflect"

type Tag uint8

type tagDefinition struct {
	typ  reflect.Type
	name string
}

var (
	variantTags   = make(map[Tag]*tagDefinition)
	tagNameLookup = make(map[string]Tag)
	tagTypeLookup = make(map[reflect.Type]Tag)
)

const (
	TagGen               Tag = 0
	TagDerivationHint    Tag = 11
	TagPubKey            Tag = 22
	TagEtcTxFlags16      Tag = 23
	TagZarcaniumTxDataV1 Tag = 39
)

func defTag[T any](tag Tag, name string) {
	variantTags[tag] = &tagDefinition{
		typ:  reflect.TypeFor[T](),
		name: name,
	}
	tagNameLookup[name] = tag

	t := reflect.TypeFor[T]()
	tagTypeLookup[t] = tag
}

func init() {
	defTag[*TxInGen](TagGen, "gen")
	defTag[[]byte](TagDerivationHint, "derivation_hint")
	defTag[Value256](TagPubKey, "pub_key")
	defTag[uint16](TagEtcTxFlags16, "etc_tx_flags16")
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

func TagFor[T any]() Tag {
	t := reflect.TypeFor[T]()
	if tag, ok := tagTypeLookup[t]; ok {
		return tag
	}
	return Tag(0xff)
}

func (t Tag) New() any {
	def, ok := variantTags[t]
	if !ok {
		panic("invalid tag")
	}
	return reflect.New(def.typ).Elem().Interface()
}

func (t Tag) Type() reflect.Type {
	def, ok := variantTags[t]
	if !ok {
		panic("invalid tag")
	}
	return def.typ
}
