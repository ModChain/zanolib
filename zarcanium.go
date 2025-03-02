package zanolib

import (
	"encoding/binary"
	"io"
)

type ZarcaniumTxDataV1 struct {
	Fee uint64
}

func (zc *ZarcaniumTxDataV1) ReadFrom(r io.Reader) (int64, error) {
	rc := rc(r)

	err := binary.Read(rc, binary.LittleEndian, &zc.Fee)
	if err != nil {
		return rc.error(err)
	}
	return rc.ret()
}
