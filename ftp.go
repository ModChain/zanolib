package zanolib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	TxHardforkId         uint64 // size_t; IN NEW VERSION FIXME
	ModeSeparateFee      uint64
	GenContext           *GenContext // if flags & TX_FLAG_SIGNATURE_MODE_SEPARATE
}

type KeyImage [32]byte // ec_point

type KeyImageIndex struct {
	OutIndex uint64
	Image    KeyImage
}

type FinalizedTx struct {
	Tx             *Transaction
	TxId           []byte
	OneTimeKey     []byte // crypto::secret_key
	FTP            *FinalizeTxParam
	HtlcOrigin     string
	OutsKeyImages  []*KeyImageIndex // pairs (out_index, key_image) for each change output
	Derivation     [32]byte         // crypto::key_derivation, a ec_point
	WasNotPrepared bool             // true if tx was not prepared/created for some good reason (e.g. not enough outs for UTXO defragmentation tx). Because we decided not to throw exceptions for non-error cases. -- sowle
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
	err = binary.Read(r, binary.LittleEndian, &res.UnlockTime)
	if err != nil {
		return nil, fmt.Errorf("while reading unlock_time: %w", err)
	}
	t, err := VarintReadUint64(r)
	if err != nil {
		return nil, fmt.Errorf("while reading extra_v count: %w", err)
	}
	if t != 0 {
		return nil, errors.New("TODO: unsupported value found, unable to read extra_v for now")
	}
	t, err = VarintReadUint64(r)
	if err != nil {
		return nil, fmt.Errorf("while reading attachment count: %w", err)
	}
	if t != 0 {
		return nil, errors.New("TODO: unsupported value found, unable to read attachment for now")
	}

	res.CryptAddress = new(AccountPublicAddr)
	_, err = res.CryptAddress.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("while reading crypt_address: %w", err)
	}

	err = binary.Read(r, binary.LittleEndian, &res.TxOutsAttr)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.LittleEndian, &res.Shuffle)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.LittleEndian, &res.Flags)
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(r, res.MultisigId[:])
	if err != nil {
		return nil, err
	}
	// read sources count
	srccnt, err := VarintReadUint64(r)
	if err != nil {
		return nil, err
	}
	res.Sources = make([]*TxSource, srccnt)
	for n := range res.Sources {
		src := new(TxSource)
		res.Sources[n] = src
		_, err = src.ReadFrom(r)
		if err != nil {
			return nil, fmt.Errorf("while reading sources[%d]: %w", n, err)
		}
	}

	seltxcnt, err := VarintReadUint64(r)
	res.SelectedTransfers = make([]uint64, seltxcnt)
	for n := range res.SelectedTransfers {
		res.SelectedTransfers[n], err = VarintReadUint64(r)
		if err != nil {
			return nil, err
		}
	}

	destscnt, err := VarintReadUint64(r)
	res.PreparedDestinations = make([]*TxDest, destscnt)
	for n := range res.PreparedDestinations {
		dest := new(TxDest)
		res.PreparedDestinations[n] = dest
		_, err = dest.ReadFrom(r)
		if err != nil {
			return nil, fmt.Errorf("while reading prepared_dest[%d]: %w", n, err)
		}
	}

	err = binary.Read(r, binary.LittleEndian, &res.ExpirationTime)
	if err != nil {
		return nil, err
	}

	_, err = io.ReadFull(r, res.SpendPubKey[:])
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.LittleEndian, &res.TxVersion)
	if err != nil {
		return nil, err
	}
	//TxHardforkId         uint64 // size_t; IN NEW VERSION FIXME
	err = binary.Read(r, binary.LittleEndian, &res.ModeSeparateFee)
	if err != nil {
		return nil, err
	}

	//final := must(io.ReadAll(r))
	//log.Printf("remaining data:\n%s", hex.Dump(final))
	return res, nil
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
