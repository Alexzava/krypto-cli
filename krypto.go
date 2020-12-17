/* 
* █▄▀ █▀█ █▄█ █▀█ ▀█▀ █▀█
* █░█ █▀▄ ░█░ █▀▀ ░█░ █▄█v1.0
*
* Simple and secure file encryption using AES-256-CTR with authenticated encryption
*
* usage:
* 	krypto -op <encrypt/decrypt> -in <inputfile> -out <outputfile>
*
*
* https://github.com/alexzava/krypto-cli
*/

package main

import (
	"fmt"
	"io"
	"bufio"
	"os"
	"log"
	"flag"
	"os/exec"
    "runtime"
	"crypto/aes"
	"crypto/hmac"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/hkdf"
)

const (
	SALT_SIZE = 16

	HMAC_KEY_LEN = 32
	HMAC_TAG_LEN = 32

	PBKDF2_ITER = 100000
	PBKDF2_KEY_LEN = 32

	ENCRYPTION_KEY_LEN = 32
	BUFFER_SIZE = 4096

	SIGNATURE = "K<3"
	SIGNATURE_LEN = 3
)

var (
	PRINT_LOG = true
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n█▄▀ █▀█ █▄█ █▀█ ▀█▀ █▀█")
	fmt.Println("█░█ █▀▄ ░█░ █▀▀ ░█░ █▄█v1.0")
	fmt.Println("https://github.com/alexzava/krypto-cli\n\n")

	// Flags
	op := flag.String("op", "", "Operation: encrypt (e) or decrypt (d) (Required)")
	in := flag.String("in", "", "Input file (Required)")
	out := flag.String("out", "", "Ouput file (Required)")
	flag.Parse()

	if len(*in) == 0 || len(*out) == 0 { 
		log.Fatal("Invalid input/output")
	}

	if *op != "e" && *op != "encrypt" && *op != "d" && *op != "decrypt" {
		log.Fatal("Invalid operations")
	}

	fmt.Printf("Warning!\nThe password will be visible while typing\n\n")

	fmt.Println("Password:")
	pass, _ := reader.ReadString('\n')

	if len(pass) == 0 {
		log.Fatal("Invalid password length")
	}

	// Clear terminal
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
        cmd.Stdout = os.Stdout
        cmd.Run()
	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("clear")
        cmd.Stdout = os.Stdout
        cmd.Run()
	}

	if *op == "e" {
		EncryptFile(pass, *in, *out)
	} else if *op == "d" {
		DecryptFile(pass, *in, *out)
	}

	fmt.Println("\nDone")
}

// Encrypt a file
// Input: password (string), inputFilePath (string), outputFilePath (string)
func EncryptFile(password string, input string, output string) {
	if _, err := os.Stat(output); err == nil {
		log.Fatal("Output file already exists")
	}

	if PRINT_LOG {
		fmt.Println("Generating keys...")
	}

	// Generate random Salt and IV
	keySalt := RandomBytes(SALT_SIZE)
	iv := RandomBytes(aes.BlockSize)

	// Derive master key
	masterKey := pbkdf2.Key([]byte(password), keySalt, PBKDF2_ITER, PBKDF2_KEY_LEN, sha256.New)

	// Derive encryption and hmac keys
	encryptionKey := make([]byte, ENCRYPTION_KEY_LEN)
	hmacKey := make([]byte, HMAC_KEY_LEN)
	derivedKeys := hkdf.New(sha256.New, masterKey, keySalt, []byte("DerivedKeys"))

	if _, err := io.ReadFull(derivedKeys, encryptionKey); err != nil {
        log.Fatal(err)
    }
    if _, err := io.ReadFull(derivedKeys, hmacKey); err != nil {
        log.Fatal(err)
    }

	// AES-CTR Block
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		log.Fatal(err)
	}
	stream := cipher.NewCTR(block, iv)

	// HMAC Tag
	tag := hmac.New(sha256.New, hmacKey)

	// Add keySalt and IV to tag
	tag.Write(keySalt)
	tag.Write(iv)

	// Open input file
	inFile, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}
	defer inFile.Close()
	stat, _ := inFile.Stat()
	fileSize := stat.Size()

	// Create output file
	outFile, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
	    log.Fatal(err)
	}
	defer outFile.Close()

	// Allocate hash tag bytes + signature bytes
	placeholder := make([]byte, HMAC_TAG_LEN + SIGNATURE_LEN)
	for i := 0; i < HMAC_TAG_LEN + SIGNATURE_LEN; i++ {
		placeholder[i] = 0
	}
	if _, err := outFile.Write(placeholder); err != nil {
		outFile.Close()
		log.Fatal(err)
	}

	// Write keySalt and IV to output file
	if _, err := outFile.Write(append(keySalt, iv...)); err != nil {
		outFile.Close()
		log.Fatal(err)
	}

	if PRINT_LOG {
		fmt.Println("Encrypting...")
	}

	// Read and encrypt file
	buffer := make([]byte, BUFFER_SIZE)
	status := 0
	for {
		bytesread, err := inFile.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Fatal(err)
			}
			break
		}
		status = status + bytesread

		encBuffer := make([]byte, bytesread)
		stream.XORKeyStream(encBuffer, buffer[:bytesread])

		if _, err := tag.Write(encBuffer); err != nil {
			log.Fatal(err)
		}

		if _, err := outFile.Write(encBuffer); err != nil {
			log.Fatal(err)
		}

		if PRINT_LOG {
			fmt.Printf("\r%d%%", (status * 100 / int(fileSize)))
		}
	}
	outFile.Close()

	// Get tag hash
	tagHash := tag.Sum(nil)

	// Add tag hash and signature to output file
	outFile, err = os.OpenFile(output, os.O_WRONLY, 0600)
	if err != nil {
	    log.Fatal(err)
	}
	defer outFile.Close()

	if _, err := outFile.Write(append([]byte(SIGNATURE), tagHash...)); err != nil {
		log.Fatal(err)
	}
	outFile.Close()
}

// Decrypt a file
// Input: password (string), inputFilePath (string), outputFilePath (string)
func DecryptFile(password string, input string, output string) {
	if _, err := os.Stat(output); err == nil {
		log.Fatal("Output file already exists")
	}
	
	// Open input file
	inFile, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}
	defer inFile.Close()
	stat, _ := inFile.Stat()
	fileSize := stat.Size()

	inFile.Seek(SIGNATURE_LEN, 0)

	// Read tag, keySalt and iv
	header := make([]byte, HMAC_TAG_LEN + SALT_SIZE + aes.BlockSize)
	_, err = inFile.Read(header)
	if err != nil {
		log.Fatal(err)
	}
	expTag := header[:HMAC_TAG_LEN]
	keySalt := header[HMAC_TAG_LEN:HMAC_TAG_LEN + SALT_SIZE]
	iv := header[HMAC_TAG_LEN + SALT_SIZE:]

	if PRINT_LOG {
		fmt.Println("Generating keys...")
	}

	// Derive key
	masterKey := pbkdf2.Key([]byte(password), keySalt, PBKDF2_ITER, PBKDF2_KEY_LEN, sha256.New)

	// Derive encryption and hmac keys
	encryptionKey := make([]byte, ENCRYPTION_KEY_LEN)
	hmacKey := make([]byte, HMAC_KEY_LEN)
	derivedKeys := hkdf.New(sha256.New, masterKey, keySalt, []byte("DerivedKeys"))

	if _, err := io.ReadFull(derivedKeys, encryptionKey); err != nil {
        log.Fatal(err)
    }
    if _, err := io.ReadFull(derivedKeys, hmacKey); err != nil {
        log.Fatal(err)
    }

	// HMAC Tag
	tag := hmac.New(sha256.New, hmacKey)

	if PRINT_LOG {
		fmt.Println("Verifying data integrity...")
	}

	// Verify tag
	tag.Write(keySalt)
	tag.Write(iv)
	buffer := make([]byte, BUFFER_SIZE)
	for {
		bytesread, err := inFile.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Fatal(err)
			}
			break
		}
		if _, err := tag.Write(buffer[:bytesread]); err != nil {
			log.Fatal(err)
		}
	}
	tagHash := tag.Sum(nil)
	if(!hmac.Equal(tagHash, expTag)) {
		log.Fatal("Tags does not match")
	}

	inFile.Seek(SIGNATURE_LEN + HMAC_TAG_LEN + SALT_SIZE + aes.BlockSize, 0)

	// AES-CTR block
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		log.Fatal(err)
	}
	stream := cipher.NewCTR(block, iv)

	// Create output file
	outFile, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
	    log.Fatal(err)
	}
	defer outFile.Close()

	if PRINT_LOG {
		fmt.Println("Decrypting...")
	}

	// Read input file and decrypt
	buffer = make([]byte, BUFFER_SIZE)
	status := 0
	for {
		bytesread, err := inFile.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Fatal(err)
			}
			break
		}
		status = status + bytesread

		decBuffer := make([]byte, bytesread)
		stream.XORKeyStream(decBuffer, buffer[:bytesread])

		if err != nil {
			log.Fatal(err)
		}

		if _, err := outFile.Write(decBuffer); err != nil {
			outFile.Close()
			log.Fatal(err)
		}

		if PRINT_LOG {
			fmt.Printf("\r%d%%", (status * 100 / int(fileSize)))
		}
	}
}

// Generate random bytes
// Input: size(int)
// Output: random bytes([]byte)
func RandomBytes(size int) []byte {
	rnd := make([]byte, size)
	_, err := rand.Read(rnd)
	if err != nil {
		log.Fatal(err)
	}

	return rnd
}
