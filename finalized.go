package zanolib

import (
	"bytes"
	"errors"
	"io"
)

type FinalizedTx struct {
	Tx             *Transaction     `json:"tx"`
	TxId           Value256         `json:"txid"`         // might be zeroes?
	OneTimeKey     Value256         `json:"one_time_key"` // crypto::secret_key
	FTP            *FinalizeTxParam `json:"ftp"`
	HtlcOrigin     string           `json:"htlc_origin"`
	OutsKeyImages  []*KeyImageIndex `json:"outs_key_images,omitempty"` // pairs (out_index, key_image) for each change output
	Derivation     Value256         `json:"derivation"`                // crypto::key_derivation, a ec_point
	WasNotPrepared bool             `json:"was_not_prepared"`          // true if tx was not prepared/created for some good reason (e.g. not enough outs for UTXO defragmentation tx). Because we decided not to throw exceptions for non-error cases. -- sowle
}

func ParseFinalized(buf, viewSecretKey []byte) (*FinalizedTx, error) {
	code, err := ChaCha8GenerateKey(viewSecretKey)
	if err != nil {
		return nil, err
	}
	buf, err = ChaCha8(code, make([]byte, 8), buf)
	if err != nil {
		return nil, err
	}
	//log.Printf("decoded buffer:\n%s", hex.Dump(buf))
	r := bytes.NewReader(buf)
	res := new(FinalizedTx)
	err = Deserialize(r, res)
	if err != nil {
		return nil, err
	}

	final := must(io.ReadAll(r))
	if len(final) != 0 {
		//log.Printf("remaining data:\n%s", hex.Dump(final))
		return nil, errors.New("trailing data")
	}
	return res, nil
}
