package main

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/foxboron/swtpm_test"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (

	// Default SRK handle
	srkHandle tpmutil.Handle = 0x81000001

	// Default SRK handle
	localHandle tpmutil.Handle = 0x81010004

	srkTemplate = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	// This uses RSA/ES
	// TODO: Add test with RSA/AOEP stuff
	rsaKeyParamsDecrypt = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault & ^tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{
			Sign:       &tpm2.SigScheme{},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
)

func TestCreateEncryptionKey(t *testing.T) {
	var sealedHandle tpmutil.Handle
	var tpmPublicKeyDigest tpmutil.U16Bytes
	tpm := swtpm_test.NewSwtpm(t.TempDir())
	socket, err := tpm.Socket()
	if err != nil {
		t.Fatal(err)
	}
	rwc, err := tpm2.OpenTPM(socket)
	if err != nil {
		t.Fatal(err)
	}

	handle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		t.Fatalf("failed CreatedPrimary")
	}
	if err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, handle, srkHandle); err != nil {
		t.Fatalf("failed EvictControl")
	}
	t.Run("create key, persistent", func(t *testing.T) {
		priv, pub, _, _, _, err := tpm2.CreateKey(rwc, handle, tpm2.PCRSelection{}, "", "", rsaKeyParamsDecrypt)
		if err != nil {
			t.Fatalf("message: %v", err)
		}
		publicKey, err := tpm2.DecodePublic(pub)
		if err != nil {
			t.Fatalf("message: %v", err)
		}

		name, err := publicKey.Name()
		if err != nil {
			t.Fatalf("message: %v", err)
		}

		tpmPublicKeyDigest = name.Digest.Value

		sealedHandle, _, err = tpm2.Load(rwc, srkHandle, "", pub, priv)
		if err != nil {
			t.Fatalf("failed to load")
		}
		defer tpm2.FlushContext(rwc, sealedHandle)
		if err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, sealedHandle, localHandle); err != nil {
			t.Fatalf("failed to evict handle: %v", err)
		}
	})

	t.Run("read persistent key", func(t *testing.T) {
		pub, _, _, err := tpm2.ReadPublic(rwc, localHandle)
		if err != nil {
			t.Fatalf("failed to Read Public: %v", err)
		}
		name, err := pub.Name()
		if err != nil {
			t.Fatalf("can't read public name: %v", err)
		}
		if !reflect.DeepEqual(name.Digest.Value, tpmPublicKeyDigest) {
			t.Fatalf("did not get the same key")
		}
	})

	t.Run("read persistent key", func(t *testing.T) {
		pub, _, _, err := tpm2.ReadPublic(rwc, localHandle)
		if err != nil {
			t.Fatalf("failed to Read Public: %v", err)
		}
		name, err := pub.Name()
		if err != nil {
			t.Fatalf("can't read public name: %v", err)
		}
		if !reflect.DeepEqual(name.Digest.Value, tpmPublicKeyDigest) {
			t.Fatalf("did not get the same key")
		}
	})

	t.Run("Encrypt/Decrypt", func(t *testing.T) {
		msg := []byte("test")
		scheme := &tpm2.AsymScheme{Alg: tpm2.AlgRSAES, Hash: tpm2.AlgNull}
		b, err := tpm2.RSAEncrypt(rwc, localHandle, msg, scheme, "")
		if err != nil {
			t.Fatalf("failed RSAEncrypt: %v", err)
		}
		b, err = tpm2.RSADecrypt(rwc, localHandle, "", b, scheme, "")
		if err != nil {
			t.Fatalf("failed RSADecrypt: %v", err)
		}
		fmt.Println(string(b))
		if !bytes.Equal(msg, b) {
			t.Fatalf("didn't match encrypted and decrypted things")
		}
	})
}
