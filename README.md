# KRYPTO-CLI

```
█▄▀ █▀█ █▄█ █▀█ ▀█▀ █▀█
█░█ █▀▄ ░█░ █▀▀ ░█░ █▄█v1.0
```

Simple and secure file encryption using AES-256-CTR with authenticated encryption

## How to use

```
krypto -op <encrypt/decrypt> -in <inputfile> -out <outputfile>
```

## How does it work?

Krypto uses AES with a key length of 256bit, CTR as block mode and HMAC-SHA256 for Encrypt-then-Mac operation as authenticated encryption.

* Generate random *iv* (16 byte) for encryption
* Generate random *salt* (16 byte) for *master key*
* Keys
	* Genereate a *master key* (32 byte) from user password using PBKDF2 with 100000 iterations
	* Derive *encryption key* (32 byte) from *master key* using HKDF
	* Derive *mac key* (32byte) from *master key* using HKDF
* Encrypt with AES-CTR
* Calculate *tag* with *iv + salt + ciphertext* using HMAC-SHA256

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

**This software has been made for personal and educational purposes.**