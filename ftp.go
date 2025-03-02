package zanolib

import (
	"bytes"
)

type FinalizeTxParam struct {
	UnlockTime           uint64
	Extra                []*Payload         // currency::extra_v
	Attachments          []*Payload         // currency::attachment_v
	CryptAddress         *AccountPublicAddr // currency::account_public_address
	TxOutsAttr           uint8
	Shuffle              bool
	Flags                uint8
	MultisigId           [32]byte    // crypto::hash
	Sources              []*TxSource // currency::tx_source_entry
	SelectedTransfers    []uint64
	PreparedDestinations []*TxDest // currency::tx_destination_entry
	ExpirationTime       uint64
	SpendPubKey          [32]byte // only for validations
	TxVersion            uint64
	//TxHardforkId         uint64 // size_t; IN NEW VERSION FIXME
	ModeSeparateFee uint64
	GenContext      *GenContext // if flags & TX_FLAG_SIGNATURE_MODE_SEPARATE
}

type KeyImageIndex struct {
	OutIndex uint64
	Image    [32]byte // ec_point
}

func ParseFTP(buf, viewSecretKey []byte) (*FinalizeTxParam, error) {
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
	res := new(FinalizeTxParam)

	err = Deserialize(r, res)
	if err != nil {
		return nil, err
	}
	//final := must(io.ReadAll(r))
	//log.Printf("remaining data:\n%s", hex.Dump(final))
	return res, nil
}
