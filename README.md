[![GoDoc](https://godoc.org/github.com/ModChain/zanolib?status.svg)](https://godoc.org/github.com/ModChain/zanolib)

# zanolib

Zano interactions library, including address manipulation.

# Offline signatures

Compatible Zano version: __2.0.1.367__

This library is able to load unsigned transactions. There are however a few caveats there:

* Because the unsigned transaction is a binary format meant to be portable, it only work between specific versions of Zano. This library is tested against a specific version of Zano and may not work with newer versions. Blob files aren't versioned so it would be difficult to detect structure automatically as is.
