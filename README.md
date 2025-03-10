[![GoDoc](https://godoc.org/github.com/ModChain/zanolib?status.svg)](https://godoc.org/github.com/ModChain/zanolib)

# zanolib

Zano interactions library, including address manipulation.

The goal is to allow full control over signatures performed when using Zano's simplewallet in view-only mode on edge nodes. The view-only wallet can have a RPC enabled that allows monitoring balance, new transactions, and generate unsigned transactions. An unsigned transaction generated by simplewallet can be then passed to this library for signature.

The goal is to implement more secure processes to store the secret, if possible.

# Offline signatures

Compatible Zano version: __2.1.0.382__

This library is able to load unsigned transactions. There are however a few caveats there:

* Because the unsigned transaction is a binary format **NOT** meant to be portable, it only work between specific versions of Zano. This library is tested against a specific version of Zano and may not work with newer versions. Blob files aren't versioned so it would be difficult to detect structure automatically as is.
* For now this library only supports simple ZC→ZC transactions.

## Usage

```go
// first, initialize a wallet based on a securely stored secret
// note: set flag to 1 if this is an auditable wallet
wallet, err := zanolib.LoadSpendSecret(secret, 0)
if err != nil {
    // ...
}
// read the finalize tx params structure
ftp, err := wallet.ParseFTP(must(os.ReadFile("zano_tx_unsigned")))
if err != nil {
    // ...
}
// inspect ftp to make sure this is the transaction you want to sign
// generate finalized transaction
finalized, err := wallet.Sign(rand.Reader, ftp, nil)
if err != nil {
    // ...
}
// write to disk
os.WriteFile("zano_tx_signed", must(wallet.Encrypt(finalized)), 0600)
// now you can pass zano_tx_signed to your view only wallet for broadcast
```
