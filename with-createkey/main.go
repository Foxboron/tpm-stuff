package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
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

func defaultEKAuthPolicy() []byte {
	buf, err := tpmutil.Pack(tpm2.CmdPolicySecret, tpm2.HandleEndorsement)
	if err != nil {
		panic(err)
	}
	digest1 := sha256.Sum256(append(make([]byte, 32), buf...))
	// We would normally append the policy buffer to digest1, but the
	// policy buffer is empty for the default Auth Policy.
	digest2 := sha256.Sum256(digest1[:])
	return digest2[:]
}

var (
	encryptionCertNVIndex     = tpmutil.Handle(0x81000100)
	commonSrkEquivalentHandle = tpmutil.Handle(0x81000001)

	certAuthHandler  = tpmutil.Handle(0x81010100)
	EKReservedHandle = tpmutil.Handle(0x81010001)

	tpmPath = "/dev/tpm1"

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

	defaultEKTemplateRSA = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: (tpm2.FlagStorageDefault | tpm2.FlagAdminWithPolicy) & ^tpm2.FlagUserWithAuth,
		AuthPolicy: defaultEKAuthPolicy(),
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256), // public.unique must be all zeros
		},
	}

	rsaKeyParams = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
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

func getPrimary(rw io.ReadWriter, hier, handle tpmutil.Handle, tmpl tpm2.Public) (tpmutil.Handle, error) {
	_, _, _, err := tpm2.ReadPublic(rw, handle)
	// TODO: Compare template with result
	if err == nil {
		return handle, nil
	}
	tpm2.EvictControl(rw, "", hier, handle, handle)
	fmt.Println("creating primary")
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{23}}

	pkh, _, err := tpm2.CreatePrimary(rw,
		hier,
		pcrSelection,
		"", "",
		tmpl)
	if err != nil {
		return tpmutil.Handle(0), fmt.Errorf("error creating Primary %v", err)
	}
	defer tpm2.FlushContext(rw, pkh)

	if err = tpm2.EvictControl(rw, "", hier, pkh, handle); err != nil {
		return tpmutil.Handle(0), fmt.Errorf("getPrimary: EvictControl failed: %v", err)
	}
	return handle, nil
}

func createKey(keyHandle tpmutil.Handle, template tpm2.Public) error {
	rw, err := OpenTPM()
	if err != nil {
		return err
	}
	defer rw.Close()

	_, err = getPrimary(rw, tpm2.HandleOwner, commonSrkEquivalentHandle, defaultSRKTemplate)
	if err != nil {
		return err
	}

	_, _, _, err = tpm2.ReadPublic(rw, encryptionCertNVIndex)
	// TODO: Compare template with result
	if err == nil {
		return nil
	}

	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{23}}

	blob, pub, _, _, _, err := tpm2.CreateKey(rw, commonSrkEquivalentHandle, pcrSelection, "", "", rsaKeyParams)
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

func AuthCommand(rw io.ReadWriteCloser, password []byte, pcrSel tpm2.PCRSelection) (tpm2.AuthCommand, error) {
	session, _, err := tpm2.StartAuthSession(
		rw,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return tpm2.AuthCommand{}, fmt.Errorf("StartAuthSession failed: %v", err)
	}
	// defer tpm2.FlushContext(rw, session)

	// if err = tpm2.PolicyPCR(rw, session, nil, pcrSel); err != nil {
	// 	return tpm2.AuthCommand{}, fmt.Errorf("PolicyPCR failed: %v", err)
	// }

	// if err := tpm2.PolicyPassword(rw, session); err != nil {
	// 	return tpm2.AuthCommand{}, fmt.Errorf("unable to require password for auth policy: %v", err)
	// }

	if _, _, err := tpm2.PolicySecret(rw, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, session, nil, nil, nil, 0); err != nil {
		return tpm2.AuthCommand{}, fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommand := tpm2.AuthCommand{Session: session, Attributes: tpm2.AttrContinueSession}
	return authCommand, nil
}

func createKeyAuthSession(handle tpmutil.Handle, template tpm2.Public) error {
	rw, err := OpenTPM()
	if err != nil {
		return err
	}
	defer rw.Close()

	_, _, _, err = tpm2.ReadPublic(rw, encryptionCertNVIndex)
	// TODO: Compare template with result
	if err == nil {
		return nil
	}
	_, err = getPrimary(rw, tpm2.HandleEndorsement, EKReservedHandle, defaultEKTemplateRSA)
	if err != nil {
		return err
	}

	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{23}}
	auth, err := AuthCommand(rw, []byte(defaultPassword), pcrSelection)
	if err != nil {
		return err
	}

	// pol, err := tpm2.PolicyGetDigest(rw, auth.Session)
	// if err != nil {
	// 	return fmt.Errorf("failed getting digest")
	// }

	// rsaKeyParams.AuthPolicy = pol

	// Remember to flush auth session
	defer tpm2.FlushContext(rw, auth.Session)

	_, _, _, _, _, err = tpm2.CreateKeyUsingAuth(rw, EKReservedHandle, pcrSelection, auth, "", rsaKeyParams)
	if err != nil {
		return fmt.Errorf("CreateKey() failed: %v", err)
	}
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
		// err := createKey(encryptionCertNVIndex, rsaKeyParams)
		err := createKeyAuthSession(certAuthHandler, rsaKeyParams)
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
