package zanocrypto

import (
	"iter"
	"reflect"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

type Mat2[T interface {
	Bytes() []byte
	Add(x, y T) T
	Subtract(x, y T) T
}] struct {
	W, H int
	D    []T
}

func NewMatrix2[T interface {
	Bytes() []byte
	Add(x, y T) T
	Subtract(x, y T) T
}](w, h int) *Mat2[T] {
	res := &Mat2[T]{
		W: w,
		H: h,
		D: make([]T, w*h),
	}
	return res
}

func (m *Mat2[T]) Set(x, y int, v T) {
	m.D[x*m.W+y] = v
}

func (m *Mat2[T]) At(x, y int) T {
	return m.D[x*m.W+y]
}

func (m *Mat2[T]) SetAll(v T) {
	for n := range m.D {
		m.D[n] = v
	}
}

func (m *Mat2[T]) SetAllCB(v func() T) {
	for n := range m.D {
		m.D[n] = v()
	}
}

func (m *Mat2[T]) Row(x int) iter.Seq2[int, T] {
	return func(yield func(int, T) bool) {
		for y := 0; y < m.H; y++ {
			if !yield(y, m.D[x*m.W+y]) {
				break
			}
		}
	}
}

func (m *Mat2[T]) IterW() iter.Seq[int] {
	end := m.W
	return func(yield func(int) bool) {
		for v := 0; v < end; v++ {
			if !yield(v) {
				break
			}
		}
	}
}

func (m *Mat2[T]) IterH() iter.Seq[int] {
	end := m.H
	return func(yield func(int) bool) {
		for v := 0; v < end; v++ {
			if !yield(v) {
				break
			}
		}
	}
}

func (m *Mat2[T]) Zero() {
	t := reflect.TypeFor[T]().Elem()
	for i := range m.D {
		m.D[i] = reflect.New(t).Interface().(T)
	}
}

func (m *Mat2[T]) Add(v T) *Mat2[T] {
	res := &Mat2[T]{
		W: m.W,
		H: m.H,
		D: make([]T, len(m.D)),
	}

	t := reflect.TypeFor[T]().Elem()
	for i := range m.D {
		res.D[i] = reflect.New(t).Interface().(T).Add(m.D[i], v)
	}

	return res
}

func (m *Mat2[T]) Subtract(v T) *Mat2[T] {
	res := &Mat2[T]{
		W: m.W,
		H: m.H,
		D: make([]T, len(m.D)),
	}

	t := reflect.TypeFor[T]().Elem()
	for i := range m.D {
		res.D[i] = reflect.New(t).Interface().(T).Subtract(m.D[i], v)
	}

	return res
}

func (m *Mat2[T]) calcHs() *edwards25519.Scalar {
	h := sha3.NewLegacyKeccak256()
	for _, v := range m.D {
		h.Write(v.Bytes())
	}

	var wideB [64]byte
	copy(wideB[:], h.Sum(nil))

	return must(new(edwards25519.Scalar).SetUniformBytes(wideB[:]))
}
