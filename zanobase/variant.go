package zanobase

import (
	"encoding/json"
	"fmt"
)

type Variant struct {
	Tag   Tag
	Value any // any type stored as a boost::variant
}

// Payload type is actually Variant
//
// Deprecated: use Variant, this will be removed
type Payload = Variant

type marshalledVariant struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

func (p *Variant) MarshalJSON() ([]byte, error) {
	obj := &marshalledVariant{
		Value: p.Value,
	}
	if v, ok := variantTags[p.Tag]; ok {
		obj.Type = v.name
	} else {
		obj.Type = fmt.Sprintf("unknown#%d", p.Tag)
	}
	return json.Marshal(obj)
}

func VariantFor[T any](obj T) *Variant {
	return &Variant{Tag: TagFor[T](), Value: obj}
}

func VariantAs[T any](p *Variant) T {
	return p.Value.(T)
}
