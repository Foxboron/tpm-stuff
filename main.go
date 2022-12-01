package main

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	emptyPassword   = ""
	defaultPassword = "1234"
)

var (
	encryptionCertNVIndex     = tpmutil.Handle(0x81000100)
	commonSrkEquivalentHandle = tpmutil.Handle(0x81000001)

	tpmPath = "/dev/tpm0"

	defaultSRKTemplate = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			ModulusRaw: make([]byte, 256),
			KeyBits:    2048,
		},
	}

	rsaKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func OpenTPM() (io.ReadWriteCloser, error) {
	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", tpmPath, err)
		return nil, err
	}
	return rwc, nil
}

func getPrimary(rw io.ReadWriter) (tpmutil.Handle, error) {
	_, _, _, err := tpm2.ReadPublic(rw, commonSrkEquivalentHandle)
	// TODO: Compare template with result
	if err == nil {
		return commonSrkEquivalentHandle, nil
	}
	tpm2.EvictControl(rw, "", tpm2.HandleOwner, commonSrkEquivalentHandle, commonSrkEquivalentHandle)
	fmt.Println("creating primary")
	pcrSelection := tpm2.PCRSelection{}

	pkh, _, err := tpm2.CreatePrimary(rw,
		tpm2.HandleOwner,
		pcrSelection,
		"", "",
		defaultSRKTemplate)
	if err != nil {
		return tpmutil.Handle(0), fmt.Errorf("Error creating Primary %v", err)
	}
	defer tpm2.FlushContext(rw, pkh)

	if err = tpm2.EvictControl(rw, "", tpm2.HandleOwner, pkh, commonSrkEquivalentHandle); err != nil {
		return tpmutil.Handle(0), fmt.Errorf("getPrimary: EvictControl failed: %v", err)
	}
	return commonSrkEquivalentHandle, nil
}

func createKey(keyHandle tpmutil.Handle, template tpm2.Public) error {
	// TODO:
	// - password
	// - auth session
	rw, err := OpenTPM()
	if err != nil {
		return err
	}
	defer rw.Close()

	_, err = getPrimary(rw)
	if err != nil {
		return err
	}

	_, _, _, err = tpm2.ReadPublic(rw, encryptionCertNVIndex)
	// TODO: Compare template with result
	if err == nil {
		return nil
	}

	blob, pub, _, _, _, err := tpm2.CreateKey(rw, commonSrkEquivalentHandle, tpm2.PCRSelection{}, "", "", rsaKeyParams)
	if err != nil {
		return fmt.Errorf("CreateKey() failed: %v", err)
	}

	loadedHandle, _, err := tpm2.Load(rw, commonSrkEquivalentHandle, "", pub, blob)
	if err != nil {
		return fmt.Errorf("error loading hash key %v", err)
	}
	defer tpm2.FlushContext(rw, loadedHandle)

	// if err = tpm2.EvictControl(rw, "", tpm2.HandleOwner, encryptionCertNVIndex, encryptionCertNVIndex); err != nil {
	// 	return fmt.Errorf("createKey: EvictControl2 failed: %v", err)
	// }
	if err = tpm2.EvictControl(rw, "", tpm2.HandleOwner, loadedHandle, encryptionCertNVIndex); err != nil {
		return fmt.Errorf("createKey: EvictControl2 failed: %v", err)
	}
	defer tpm2.FlushContext(rw, encryptionCertNVIndex)
	fmt.Println("Created key")
	return nil
}

func listkey(handle tpmutil.Handle) {
	rw, err := OpenTPM()
	if err != nil {
		log.Fatal(err)
	}
	defer rw.Close()

	tpmPublic, _, _, err := tpm2.ReadPublic(rw, handle)
	if err != nil {
		fmt.Println("no keys")
		log.Fatal(err)
	}

	publicKey, err := tpmPublic.Key()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(publicKey)
}

func signFile(handle tpmutil.Handle) error {
	rw, err := OpenTPM()
	if err != nil {
		log.Fatal(err)
	}
	defer rw.Close()

	b, _ := os.ReadFile("testfile")

	digest, khValidation, err := tpm2.Hash(rw, tpm2.AlgSHA256, b, tpm2.HandleOwner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hash failed unexpectedly: %v", err)
		return nil
	}

	sig, err := tpm2.Sign(rw, handle, "", digest[:], khValidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error Signing: %v", err)
	}
	fmt.Fprintf(os.Stderr, "Signature data:  %s\n", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))
	os.WriteFile("testfile.sig", sig.RSA.Signature, 0644)
	return nil
}

func verifyFile(handle tpmutil.Handle) error {
	rw, err := OpenTPM()
	if err != nil {
		log.Fatal(err)
	}
	defer rw.Close()
	tpmPublic, _, _, err := tpm2.ReadPublic(rw, handle)
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := tpmPublic.Key()
	if err != nil {
		log.Fatal(err)
	}

	fBytes, _ := os.ReadFile("testfile")
	sigBytes, _ := os.ReadFile("testfile.sig")

	hsh := crypto.SHA256.New()
	hsh.Write(fBytes)

	rsaPub := *publicKey.(*rsa.PublicKey)

	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, hsh.Sum(nil), sigBytes); err != nil {
		fmt.Fprintf(os.Stderr, "VerifyPKCS1v15 failed: %v", err)
	}
	fmt.Println("valid file")
	return nil
}

func clearkeys(handle tpmutil.Handle) error {
	rw, err := OpenTPM()
	if err != nil {
		log.Fatal(err)
	}
	defer rw.Close()
	if err = tpm2.EvictControl(rw, "", tpm2.HandleOwner, handle, handle); err != nil {
		log.Fatal(err)
	}
	fmt.Println("cleared keys")
	return nil
}

// tpm2 createprimary --output primary.ctx
// tpm2 createpolicy --policy-pcr --pcr-list sha256:0,2,3,7 --policy pcr.pol
// tpm2 create --context-parent primary.ctx --policy-file pcr.pol --object-attributes --pubfile key.pub --privfile key.priv

func main() {
	if len(os.Args) == 1 {
		fmt.Println("needs more than one arg")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "create-keys":
		err := createKey(encryptionCertNVIndex, rsaKeyParams)
		if err != nil {
			log.Fatal(err)
		}
	case "list-keys":
		listkey(encryptionCertNVIndex)
	case "sign":
		if err := signFile(encryptionCertNVIndex); err != nil {
			log.Fatal(err)
		}
	case "clear-keys":
		if err := clearkeys(encryptionCertNVIndex); err != nil {
			log.Fatal(err)
		}
	case "verify":
		if err := verifyFile(encryptionCertNVIndex); err != nil {
			log.Fatal(err)
		}
	case "reseal":
	}
}
