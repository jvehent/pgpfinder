package main

import (
	"bufio"
	"code.google.com/p/go.crypto/openpgp"
	"crypto/rsa"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	var keyserver = flag.String("ks", "http://gpg.mozilla.org:80", "Key server. Default uses Mozilla's.")
	var search = flag.String("search", "someuser@example.net", "Search string. May return multiple results.")
	var id = flag.String("id", "0xA3D652173B763E8F", "Key ID to retrieve. Returns only one result.")
	flag.Parse()
	var err error
	var keys []io.ReadCloser
	if *search != "someuser@example.net" {
		keys, err = SearchAndReturn(*search, *keyserver)
		if err != nil {
			panic(err)
		}
	} else {
		key, err := GetKeyByID(*id, *keyserver)
		if err != nil {
			panic(err)
		}
		keys = append(keys, key)
	}

	for _, key := range keys {
		// Load PGP public key
		els, err := openpgp.ReadArmoredKeyRing(key)
		if err != nil {
			panic(err)
		}
		if len(els) != 1 {
			err = fmt.Errorf("Public GPG Key contains %d entities, wanted 1\n", len(els))
			panic(err)
		}
		for _, el := range els {
			keyid := strconv.FormatUint(el.PrimaryKey.KeyId, 16)
			fmt.Printf("\n------- Details of Key ID %s\n", strings.ToUpper(keyid))

			fingerprint := hex.EncodeToString(el.PrimaryKey.Fingerprint[:])
			fmt.Println("Fingerprint:", strings.ToUpper(fingerprint))

			fmt.Println("Creation Time:", el.PrimaryKey.CreationTime)

			switch el.PrimaryKey.PubKeyAlgo {
			case 1:
				fmt.Println("Pubkey algorithm: RSA")
				parseRSAPubKey(el.PrimaryKey.PublicKey.(*rsa.PublicKey))
			case 2:
				fmt.Println("Pubkey algorithm: RSA Encrypt Only")
			case 3:
				fmt.Println("Pubkey algorithm: RSA Sign Only")
			case 16:
				fmt.Println("Pubkey algorithm: ElGamal")
			case 17:
				fmt.Println("Pubkey algorithm: DSA")
			case 18:
				fmt.Println("Pubkey algorithm: ECDH")
			case 19:
				fmt.Println("Pubkey algorithm: ECDSA")
			}

			fmt.Println("Identities:")
			for name, id := range el.Identities {
				fmt.Println("-", name)
				fmt.Println("\tsignatures:")
				for _, sig := range id.Signatures {
					hexsig := strconv.FormatUint(*sig.IssuerKeyId, 16)
					fmt.Println("\t-", strings.ToUpper(hexsig), sig.CreationTime.String())
				}
			}
		}
		key.Close()
		fmt.Printf("\n-------------------------------\n")
	}
}

func parseRSAPubKey(pubkey *rsa.PublicKey) (err error) {
	fmt.Println("Public Modulus:", pubkey.N.BitLen(), "bits. Public exponent:", pubkey.E)
	return
}

func SearchAndReturn(search, keyserver string) (keys []io.ReadCloser, err error) {
	reqstr := fmt.Sprintf("%s/pks/lookup?op=vindex&options=mr&search=%s", keyserver, search)
	fmt.Println("searching at", reqstr)
	resp, err := http.Get(reqstr)
	if err != nil {
		return
	}
	// parse the body, find all `pub` lines
	scanner := bufio.NewScanner(resp.Body)
	pubre := regexp.MustCompile(`^pub:[0-9ABCDEF]{8}`)
	for scanner.Scan() {
		if pubre.MatchString(scanner.Text()) {
			keyid := strings.Split(scanner.Text(), ":")[1]
			// we have a key id, now go fetch it
			var key io.ReadCloser
			key, err = GetKeyByID(keyid, keyserver)
			if err != nil {
				return
			}
			keys = append(keys, key)
		}
	}
	return
}

func GetKeyByID(keyid, keyserver string)(key io.ReadCloser, err error){
	reqstr := fmt.Sprintf("%s/pks/lookup?op=get&options=mr&search=0x%s", keyserver, keyid)
	resp, err := http.Get(reqstr)
	if err != nil {
		return
	}
	key = resp.Body
	return
}
