package zanolib

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

var (
	readerFromType = reflect.TypeOf((*io.ReaderFrom)(nil)).Elem()
	byteArrayType  = reflect.TypeFor[[]byte]()
)

// Deserialize implements epee deserializer (kind of)
func Deserialize(r ByteAndReadReader, target any) error {
	var err error

	obj := reflect.ValueOf(target)
	t := obj.Type()

	for t.Kind() == reflect.Ptr {
		if obj.IsNil() {
			obj.Set(reflect.New(t.Elem()))
		}
		if t.Implements(readerFromType) {
			_, err = obj.Interface().(io.ReaderFrom).ReadFrom(r)
			return err
		}
		obj = obj.Elem()
		t = obj.Type()
	}
	if t == byteArrayType {
		return subDeserialize(r, obj.Addr().Interface(), "!")
	}
	if t.Kind() == reflect.Slice {
		ln, err := VarintReadUint64(r)
		if err != nil {
			return err
		}
		if ln > 128 {
			return fmt.Errorf("slice too large: %d > 128", ln)
		}
		val := reflect.MakeSlice(t, int(ln), int(ln))
		for i := 0; i < int(ln); i++ {
			err = subDeserialize(r, val.Index(i).Addr().Interface(), "")
			if err != nil {
				return err
			}
		}
		obj.Set(val)
		return nil
	}
	if t.Kind() != reflect.Struct {
		return subDeserialize(r, obj.Addr().Interface(), "!")
	}

	nf := t.NumField()
	for i := 0; i < nf; i += 1 {
		tf := t.Field(i)
		tag := tf.Tag.Get("epee")
		err = subDeserialize(r, obj.Field(i).Addr().Interface(), tag)
		if err != nil {
			return err
		}
	}
	return nil
}

func subDeserialize(r ByteAndReadReader, o any, tag string) error {
	var err error
	switch v := o.(type) {
	case *bool, *uint8, *uint16:
		err = binary.Read(r, binary.LittleEndian, v)
	case *uint64:
		if tag == "varint" {
			*v, err = VarintReadUint64(r)
		} else {
			err = binary.Read(r, binary.LittleEndian, v)
		}
	case *[32]byte:
		_, err = io.ReadFull(r, v[:])
	case *string:
		ln, err := VarintReadUint64(r)
		if err != nil {
			return err
		}
		if ln > 4096 {
			return fmt.Errorf("string length too long: %d", ln)
		}
		buf := make([]byte, ln)
		_, err = io.ReadFull(r, buf)
		if err != nil {
			return err
		}
		*v = string(buf)
		return nil
	case *[]byte:
		ln, err := VarintReadUint64(r)
		if err != nil {
			return err
		}
		if ln > 4096 {
			return fmt.Errorf("string length too long: %d", ln)
		}
		*v = make([]byte, ln)
		_, err = io.ReadFull(r, *v)
		if err != nil {
			return err
		}
		return nil
	default:
		if tag == "!" {
			return fmt.Errorf("unsupported deserialize type %T", o)
		}
		err = Deserialize(r, v)

	}
	return err
}
