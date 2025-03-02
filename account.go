package zanolib

import "io"

type AccountPublicAddr struct {
	SpendKey [32]byte
	ViewKey  [32]byte
	Flags    uint8
}

func (acct *AccountPublicAddr) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.ReadFull(r, acct.SpendKey[:])
	if err != nil {
		return int64(n), err
	}
	n2, err := io.ReadFull(r, acct.ViewKey[:])
	if err != nil {
		return int64(n + n2), err
	}
	var b [1]byte
	n3, err := io.ReadFull(r, b[:])
	if err != nil {
		return int64(n + n2 + n3), err
	}
	acct.Flags = b[0]

	return int64(n + n2 + n3), nil
}
