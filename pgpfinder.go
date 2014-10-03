package main

import (
	"bufio"
	"crypto/rsa"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"code.google.com/p/go.crypto/openpgp"
)

var verbose = false

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s - Find PGP keys on a keyserver - Julien Vehent 2014\n"+
			"Usage: %s someuser@example.net someotheruser@example.com\n"+
			"Options:\n", os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	var err error
	var keys []io.ReadCloser
	found := 0
	var searches []string
	var keyserver = flag.String("ks", "http://gpg.mozilla.org:80", "Key server. Default uses Mozilla's.")
	var search = flag.String("search", "someuser@example.net", "Search string. May return multiple results.")
	var id = flag.String("id", "0xABCDEF1234567890", "Key ID to retrieve. Returns only one result.")
	var isverbose = flag.Bool("v", false, "Verbose mode")
	flag.Parse()
	if *isverbose {
		verbose = true
	}

	// search by key ID
	if *id != "0xABCDEF1234567890" {
		fmt.Println("Searching for key id", *id)
		key, found, err := GetKeyByID(*id, *keyserver)
		if found == 0 {
			fmt.Println("No key found")
			os.Exit(1)
		}
		if found > 1 {
			fmt.Println("Found", found, "keys, and that's unexpected.")
			os.Exit(1)
		}
		if err != nil {
			panic(err)
		}
		keys = append(keys, key)
		err = printKeyInfo(keys)
		if err != nil {
			panic(err)
		}
		goto exit
	}

	// search by string
	if *search != "someuser@example.net" {
		searches = append(searches, *search)
	} else {
		args := flag.Args()
		fmt.Println("Searching for the following keys:", args)
		for _, arg := range args {
			searches = append(searches, arg)
		}
	}
	for _, s := range searches {
		keys, found, err = SearchAndReturn(s, *keyserver)
		fmt.Printf("\nFound %d keys on %s for %s\n", found, *keyserver, s)
		if found < 1 {
			os.Exit(1)
		}
		if err != nil {
			panic(err)
		}
		err = printKeyInfo(keys)
		if err != nil {
			panic(err)
		}
	}
exit:
}

func printKeyInfo(keys []io.ReadCloser) (err error) {
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
			fmt.Printf("========       Details of Key ID %s       ========\n", strings.ToUpper(keyid))

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
		fmt.Printf("================================================================\n")
	}
	return
}

func parseRSAPubKey(pubkey *rsa.PublicKey) (err error) {
	fmt.Println("Public Modulus:", pubkey.N.BitLen(), "bits. Public exponent:", pubkey.E)
	return
}

func SearchAndReturn(search, keyserver string) (keys []io.ReadCloser, found int, err error) {
	reqstr := fmt.Sprintf("%s/pks/lookup?op=vindex&options=mr&search=%s", keyserver, search)
	if verbose {
		fmt.Println("searching at", reqstr)
	}
	resp, err := http.Get(reqstr)
	if err != nil {
		return
	}
	// parse the body, find all `pub` lines
	scanner := bufio.NewScanner(resp.Body)
	pubre := regexp.MustCompile(`^pub:[0-9ABCDEF]{8}`)
	for scanner.Scan() {
		if pubre.MatchString(scanner.Text()) {
			found++
			keyid := fmt.Sprintf("0x%s", strings.Split(scanner.Text(), ":")[1])
			// we have a key id, now go fetch it
			var key io.ReadCloser
			key, _, err = GetKeyByID(keyid, keyserver)
			if err != nil {
				return
			}
			keys = append(keys, key)
		}
	}
	return
}

func GetKeyByID(keyid, keyserver string) (key io.ReadCloser, found int, err error) {
	re := regexp.MustCompile(`^0x[ABCDEF0-9]{8,64}$`)
	if !re.MatchString(keyid) {
		return key, 0, fmt.Errorf("Invalid key id. Must be in format '0x[ABCDEF0-9]{8,64}")
	}
	reqstr := fmt.Sprintf("%s/pks/lookup?op=get&options=mr&search=%s", keyserver, keyid)
	if verbose {
		fmt.Println("querying", reqstr)
	}
	resp, err := http.Get(reqstr)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		return key, 0, fmt.Errorf("No key found")
	}
	found = 1
	key = resp.Body
	return
}
