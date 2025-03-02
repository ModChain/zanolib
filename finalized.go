package zanolib

import (
	"bytes"
	"io"
)

type FinalizedTx struct {
	Tx             *Transaction
	TxId           [32]byte // might be zeroes?
	OneTimeKey     [32]byte // crypto::secret_key
	FTP            *FinalizeTxParam
	HtlcOrigin     string
	OutsKeyImages  []*KeyImageIndex // pairs (out_index, key_image) for each change output
	Derivation     [32]byte         // crypto::key_derivation, a ec_point
	WasNotPrepared bool             // true if tx was not prepared/created for some good reason (e.g. not enough outs for UTXO defragmentation tx). Because we decided not to throw exceptions for non-error cases. -- sowle
}

func ParseFinalized(buf, viewSecretKey []byte) (*FinalizedTx, error) {
	code, err := Chacha8GenerateKey(viewSecretKey)
	if err != nil {
		return nil, err
	}
	buf, err = ChaCha8(code, make([]byte, 8), buf)
	if err != nil {
		return nil, err
	}
	//log.Printf("decoded buffer:\n%s", hex.Dump(buf))
	r := bytes.NewReader(buf)
	res := &FinalizedTx{}
	_, err = res.ReadFrom(r)
	if err != nil {
		return nil, err
	}

	//final := must(io.ReadAll(r))
	//log.Printf("remaining data:\n%s", hex.Dump(final))
	return res, nil
}

func (res *FinalizedTx) ReadFrom(rx io.Reader) (int64, error) {
	rc := rc(rx)

	res.Tx = &Transaction{}
	_, err := res.Tx.ReadFrom(rc)
	if err != nil {
		return rc.error(err)
	}
	_, err = io.ReadFull(rc, res.TxId[:])
	if err != nil {
		return rc.error(err)
	}
	_, err = io.ReadFull(rc, res.OneTimeKey[:])
	if err != nil {
		return rc.error(err)
	}
	res.FTP = new(FinalizeTxParam)
	err = rc.into(res.FTP)
	if err != nil {
		return rc.error(err)
	}

	buf, err := rc.readVarBytes()
	if err != nil {
		return rc.error(err)
	}
	res.HtlcOrigin = string(buf)

	res.OutsKeyImages, err = arrayOf[KeyImageIndex](rc)
	if err != nil {
		return rc.error(err)
	}

	return rc.magic(&res.Derivation, &res.WasNotPrepared)
}
