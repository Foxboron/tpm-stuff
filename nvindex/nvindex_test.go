package main

import (
	"bytes"
	"testing"

	"github.com/foxboron/swtpm_test"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	handle   tpmutil.Handle = 0x1509001
	testData                = []byte("testdata")
	attr                    = tpm2.AttrOwnerRead | tpm2.AttrOwnerWrite
)

func TestCreateEncryptionAgeKey(t *testing.T) {
	tpm := swtpm_test.NewSwtpm(t.TempDir())
	socket, err := tpm.Socket()
	if err != nil {
		t.Fatal(err)
	}
	rwc, err := tpm2.OpenTPM(socket)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Create NV Index", func(t *testing.T) {
		if err := tpm2.NVDefineSpace(rwc,
			tpm2.HandleOwner, handle,
			"", "",
			nil, attr,
			uint16(len(testData)),
		); err != nil {
			t.Fatalf("fialed defining NV space: %v", err)
		}
		if err := tpm2.NVWrite(rwc, tpm2.HandleOwner, handle, "", testData, 0); err != nil {
			t.Fatalf("NVWrite failed: %v", err)
		}
	})

	t.Run("Read NV Index", func(t *testing.T) {
		data, err := tpm2.NVReadEx(rwc, handle, tpm2.HandleOwner, "", 0)
		if err != nil {
			t.Fatalf("NVReadEx failed: %v", err)
		}
		if !bytes.Equal(data, testData) {
			t.Fatalf("Did not get the correct data")
		}
	})

	testData = []byte("new data we have included")
	t.Run("Update NV Index", func(t *testing.T) {
		if err := tpm2.NVUndefineSpace(rwc, "", tpm2.HandleOwner, handle); err != nil {
			t.Fatalf("NVUndefineSpace failed: %v", err)
		}
		if err := tpm2.NVDefineSpace(rwc,
			tpm2.HandleOwner, handle,
			"", "",
			nil, attr,
			uint16(len(testData)),
		); err != nil {
			t.Fatalf("fialed defining NV space: %v", err)
		}
		err := tpm2.NVWrite(rwc, tpm2.HandleOwner, handle, "", testData, 0)
		if err != nil {
			t.Fatalf("NVWrite failed: %v", err)
		}
	})

	t.Run("Read NV Index again", func(t *testing.T) {
		data, err := tpm2.NVReadEx(rwc, handle, tpm2.HandleOwner, "", 0)
		if err != nil {
			t.Fatalf("NVReadEx failed: %v", err)
		}
		if !bytes.Equal(data, testData) {
			t.Fatalf("Did not get the correct data")
		}
	})
}
