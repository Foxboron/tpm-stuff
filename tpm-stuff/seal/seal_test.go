package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
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

	// Default SRK template
	srkTemplate = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		AuthPolicy: nil,
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
)

func policySession(rwc io.ReadWriteCloser, password string) (sessHandle tpmutil.Handle, policy []byte, retErr error) {
	sessHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)

	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to start session: %v", err)
	}
	// defer func() {
	// 	if sessHandle != tpm2.HandleNull && err != nil {
	// 		if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
	// 			retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
	// 		}
	// 	}
	// }()

	// pcrSelection := tpm2.PCRSelection{
	// 	Hash: tpm2.AlgSHA256,
	// 	PCRs: []int{pcr},
	// }

	// An empty expected digest means that digest verification is skipped.
	// if err := tpm2.PolicyPCR(rwc, sessHandle, nil /*expectedDigest*/, pcrSelection); err != nil {
	// 	return sessHandle, nil, fmt.Errorf("unable to bind PCRs to auth policy: %v", err)
	// }

	if password != "" {
		if err := tpm2.PolicyPassword(rwc, sessHandle); err != nil {
			return sessHandle, nil, fmt.Errorf("unable to require password for auth policy: %v", err)
		}
	}

	policy, err = tpm2.PolicyGetDigest(rwc, sessHandle)
	if err != nil {
		return sessHandle, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}
	return sessHandle, policy, nil
}

func policySessionPCR(rwc io.ReadWriteCloser, pcrs []int) (sessHandle tpmutil.Handle, policy []byte, retErr error) {
	sessHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)

	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to start session: %v", err)
	}
	// defer func() {
	// 	if sessHandle != tpm2.HandleNull && err != nil {
	// 		if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
	// 			retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
	// 		}
	// 	}
	// }()

	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: pcrs,
	}

	// An empty expected digest means that digest verification is skipped.
	if err := tpm2.PolicyPCR(rwc, sessHandle, nil /*expectedDigest*/, pcrSelection); err != nil {
		return sessHandle, nil, fmt.Errorf("unable to bind PCRs to auth policy: %v", err)
	}

	policy, err = tpm2.PolicyGetDigest(rwc, sessHandle)
	if err != nil {
		return sessHandle, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}
	return sessHandle, policy, nil
}

func TestSealStuff(t *testing.T) {
	var sealedHandle tpmutil.Handle
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

	t.Run("seal secret", func(tj *testing.T) {
		sh, policy, err := policySession(rwc, "")
		defer func() {
			tpm2.FlushContext(rwc, sh)
		}()
		if err != nil {
			t.Fatalf("failed making policy")
		}
		priv, pub, err := tpm2.Seal(rwc, srkHandle, "", "", policy, []byte("test"))
		if err != nil {
			t.Fatalf("failed to seal")
		}
		sealedHandle, _, err = tpm2.Load(rwc, srkHandle, "", pub, priv)
		if err != nil {
			t.Fatalf("failed to load")
		}
	})

	t.Run("unseal secret", func(t *testing.T) {
		sess, _, err := policySession(rwc, "")
		if err != nil {
			t.Fatalf("failed making policy")
		}
		b, err := tpm2.UnsealWithSession(rwc, sess, sealedHandle, "")
		if err != nil {
			t.Fatalf("failed to unseal: %v", err)
		}
		if !bytes.Equal(b, []byte("test")) {
			t.Fatalf("failed to unseal, got: %v", b)
		}
	})

}

func TestSealWithPassword(t *testing.T) {
	var sealedHandle tpmutil.Handle
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

	secret := []byte("secret")
	pin := "test"

	t.Run("seal secret with password", func(tj *testing.T) {
		sh, policy, err := policySession(rwc, pin)
		defer func() {
			tpm2.FlushContext(rwc, sh)
		}()
		if err != nil {
			t.Fatalf("failed making policy")
		}
		priv, pub, err := tpm2.Seal(rwc, srkHandle, "", pin, policy, secret)
		if err != nil {
			t.Fatalf("failed to seal")
		}
		sealedHandle, _, err = tpm2.Load(rwc, srkHandle, "", pub, priv)
		if err != nil {
			t.Fatalf("failed to load")
		}
	})

	t.Run("unseal secret with password", func(t *testing.T) {
		sess, _, err := policySession(rwc, pin)
		if err != nil {
			t.Fatalf("failed making policy")
		}
		b, err := tpm2.UnsealWithSession(rwc, sess, sealedHandle, pin)
		if err != nil {
			t.Fatalf("failed to unseal: %v", err)
		}
		if !bytes.Equal(b, secret) {
			t.Fatalf("failed to unseal, got: %v", b)
		}
	})
}

func TestSealWithPasswordPersistent(t *testing.T) {
	var sealedHandle tpmutil.Handle
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

	secret := []byte("secret")
	pin := "test"

	t.Run("seal secret with password through persistent handle", func(tj *testing.T) {
		sh, policy, err := policySession(rwc, pin)
		defer func() {
			tpm2.FlushContext(rwc, sh)
		}()
		if err != nil {
			t.Fatalf("failed making policy")
		}
		priv, pub, err := tpm2.Seal(rwc, srkHandle, "", pin, policy, secret)
		if err != nil {
			t.Fatalf("failed to seal")
		}
		sealedHandle, _, err = tpm2.Load(rwc, srkHandle, "", pub, priv)
		if err != nil {
			t.Fatalf("failed to load")
		}
		defer tpm2.FlushContext(rwc, sealedHandle)
		if err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, sealedHandle, localHandle); err != nil {
			t.Fatalf("failed to evict handle: %v", err)
		}
	})

	t.Run("unseal secret with password through persistent handle", func(t *testing.T) {
		sess, _, err := policySession(rwc, pin)
		if err != nil {
			t.Fatalf("failed making policy")
		}
		b, err := tpm2.UnsealWithSession(rwc, sess, localHandle, pin)
		if err != nil {
			t.Fatalf("failed to unseal: %v", err)
		}
		if !bytes.Equal(b, secret) {
			t.Fatalf("failed to unseal, got: %v", b)
		}
	})
}

func TestSealWithPasswordLocalStorage(t *testing.T) {
	var sealedHandle tpmutil.Handle
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

	secret := []byte("secret")
	pin := "test"

	var priv, pub []byte

	t.Run("seal secret with password through local storage", func(tj *testing.T) {
		sh, policy, err := policySession(rwc, pin)
		defer func() {
			tpm2.FlushContext(rwc, sh)
		}()
		if err != nil {
			t.Fatalf("failed making policy")
		}
		priv, pub, err = tpm2.Seal(rwc, srkHandle, "", pin, policy, secret)
		if err != nil {
			t.Fatalf("failed to seal")
		}
	})

	t.Run("unseal secret with password through local storage", func(t *testing.T) {
		sess, _, err := policySession(rwc, pin)
		if err != nil {
			t.Fatalf("failed making policy")
		}
		sealedHandle, _, err = tpm2.Load(rwc, srkHandle, "", pub, priv)
		if err != nil {
			t.Fatalf("failed to load")
		}
		defer tpm2.FlushContext(rwc, sealedHandle)
		b, err := tpm2.UnsealWithSession(rwc, sess, sealedHandle, pin)
		if err != nil {
			t.Fatalf("failed to unseal: %v", err)
		}
		if !bytes.Equal(b, secret) {
			t.Fatalf("failed to unseal, got: %v", b)
		}
	})
}

func TestSealWithPCR(t *testing.T) {
	var sealedHandle tpmutil.Handle
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

	secret := []byte("secret")
	pin := ""

	t.Run("seal secret with pcrs", func(tj *testing.T) {
		sh, policy, err := policySessionPCR(rwc, []int{16})
		defer func() {
			tpm2.FlushContext(rwc, sh)
		}()
		if err != nil {
			t.Fatalf("failed making policy")
		}
		priv, pub, err := tpm2.Seal(rwc, srkHandle, "", pin, policy, secret)
		if err != nil {
			t.Fatalf("failed to seal")
		}
		sealedHandle, _, err = tpm2.Load(rwc, srkHandle, "", pub, priv)
		if err != nil {
			t.Fatalf("failed to load")
		}
	})

	t.Run("unseal secret with pcrs", func(t *testing.T) {
		sess, _, err := policySessionPCR(rwc, []int{16})
		if err != nil {
			t.Fatalf("failed making policy")
		}
		b, err := tpm2.UnsealWithSession(rwc, sess, sealedHandle, pin)
		if err != nil {
			t.Fatalf("failed to unseal: %v", err)
		}
		if !bytes.Equal(b, secret) {
			t.Fatalf("failed to unseal, got: %v", b)
		}
	})

	// Extend PCR

	pcrValue := bytes.Repeat([]byte{0xB}, sha256.Size)
	if err := tpm2.PCRExtend(rwc, tpmutil.Handle(16), tpm2.AlgSHA256, pcrValue, ""); err != nil {
		t.Fatalf("failed to extend pcr: %v", err)
	}

	t.Run("unseal secret with changed pcrs", func(t *testing.T) {
		sess, _, err := policySessionPCR(rwc, []int{16})
		if err != nil {
			t.Fatalf("failed making policy")
		}
		_, err = tpm2.UnsealWithSession(rwc, sess, sealedHandle, pin)
		if err == nil {
			t.Fatalf("we didn't detect the changed PCR")
		}
	})
}

func TestSealWithFuturePCR(t *testing.T) {
	var sealedHandle tpmutil.Handle
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

	secret := []byte("secret")
	pin := ""

	t.Run("seal secret with pcrs", func(tj *testing.T) {
		sh, policy, err := policySessionPCR(rwc, []int{16})
		defer func() {
			tpm2.FlushContext(rwc, sh)
		}()
		if err != nil {
			t.Fatalf("failed making policy")
		}
		priv, pub, err := tpm2.Seal(rwc, srkHandle, "", pin, policy, secret)
		if err != nil {
			t.Fatalf("failed to seal")
		}
		sealedHandle, _, err = tpm2.Load(rwc, srkHandle, "", pub, priv)
		if err != nil {
			t.Fatalf("failed to load")
		}
	})

	t.Run("unseal secret with pcrs", func(t *testing.T) {
		sess, _, err := policySessionPCR(rwc, []int{16})
		if err != nil {
			t.Fatalf("failed making policy")
		}
		b, err := tpm2.UnsealWithSession(rwc, sess, sealedHandle, pin)
		if err != nil {
			t.Fatalf("failed to unseal: %v", err)
		}
		if !bytes.Equal(b, secret) {
			t.Fatalf("failed to unseal, got: %v", b)
		}
	})

	// Extend PCR

	pcrValue := bytes.Repeat([]byte{0xB}, sha256.Size)
	if err := tpm2.PCRExtend(rwc, tpmutil.Handle(16), tpm2.AlgSHA256, pcrValue, ""); err != nil {
		t.Fatalf("failed to extend pcr: %v", err)
	}

	t.Run("unseal secret with changed pcrs", func(t *testing.T) {
		sess, _, err := policySessionPCR(rwc, []int{16})
		if err != nil {
			t.Fatalf("failed making policy")
		}
		_, err = tpm2.UnsealWithSession(rwc, sess, sealedHandle, pin)
		if err == nil {
			t.Fatalf("we didn't detect the changed PCR")
		}
	})
}
