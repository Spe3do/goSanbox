package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
)

type HashInfo struct {
	Md5    string `json:"md5"`
	Sha1   string `json:"sha1"`
	Sha256 string `json:"sha256"`
	Sha512 string `json:"sha512"`
}

func CaclucateBasiHashes(rd io.Reader) HashInfo {
	md5 := md5.New()
	sha1 := sha1.New()
	sha256 := sha256.New()
	sha512 := sha512.New()

	//For optimum speed, Getpagesize return the underlying system's memory page size.
	pagesize := os.Getpagesize()

	//wraps the Reader object into a new buffered reader to read the files in chunks
	//and buffering them for performance
	reader := bufio.NewReaderSize(rd, pagesize)

	//creates a mutiplexer Wirter obejc that will duplicate all write
	//operations when copying data from source into all different hashing algorithms
	//at the same time
	multiWriter := io.MultiWriter(md5, sha1, sha256, sha512)

	//using a bffered reader, this will wirte to the writer multiplexer
	//so we only traverse through the file one, and can calculate all hashes
	//in a singel byte buffered scan pass
	_, err := io.Copy(multiWriter, reader)
	if err != nil {
		panic(err.Error())
	}

	var info HashInfo

	info.Md5 = hex.EncodeToString(md5.Sum(nil))
	info.Sha1 = hex.EncodeToString(sha1.Sum(nil))
	info.Sha256 = hex.EncodeToString(sha256.Sum(nil))
	info.Sha512 = hex.EncodeToString(sha512.Sum(nil))

	return info

}

func main() {
	args := os.Args[1:]

	var filename string
	filename = args[0]

	//open an io.Reader from the file we eould like to calculate hashes
	f, err := os.OpenFile(filename, os.O_RDONLY, 0)
	if err != nil {
		log.Fatalln("Cannot open file: %s", filename)
	}
	defer f.Close()

	info := CaclucateBasiHashes(f)

	fmt.Println("md5	:", info.Md5)
	fmt.Println("sha1	:", info.Sha1)
	fmt.Println("sha256	:", info.Sha256)
	fmt.Println("sha512	:", info.Sha512)
	fmt.Println()
}
