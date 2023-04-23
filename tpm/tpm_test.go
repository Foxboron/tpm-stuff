package main

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/foxboron/swtpm_test"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/exp/maps"
)

func ReadAllPCRs(rw io.ReadWriter) (map[int][]byte, error) {
	ret := make(map[int][]byte)
	pcrs := [][]int{
		{0, 1, 2, 3, 4, 5, 7},
		{8, 9, 10, 11, 12, 13, 14, 15},
		{16, 17, 18, 19, 20, 21, 22, 23},
	}
	for _, l := range pcrs {
		sel, err := tpm2.ReadPCRs(rw, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: l})
		if err != nil {
			return nil, err
		}
		maps.Copy(ret, sel)
	}
	return ret, nil
}

func TestPCRStuff(t *testing.T) {
	tpm := swtpm_test.NewSwtpm(t.TempDir())
	socket, err := tpm.Socket()
	if err != nil {
		t.Fatal(err)
	}
	rw, err := tpm2.OpenTPM(socket)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("all zero PCR values", func(t *testing.T) {
		pcrs, err := ReadAllPCRs(rw)
		if err != nil {
			t.Fatal(err)
		}
		coal := func(bytes []byte) byte {
			b := byte(0)
			for _, s := range bytes {
				b |= s
			}
			return b
		}
		for _, p := range pcrs {
			if coal(p) != 0x0 && coal(p) != 0xFF {
				t.Fatal("found something weird")
			}
		}
	})

	t.Run("Extend a PCR value", func(t *testing.T) {
		const pcr = int(16)
		pcrBefore, err := tpm2.ReadPCR(rw, pcr, tpm2.AlgSHA256)
		if err != nil {
			t.Fatalf("failed fetching PCR")
		}

		pcrValue := bytes.Repeat([]byte{0xB}, sha256.Size)
		if err := tpm2.PCRExtend(rw, tpmutil.Handle(pcr), tpm2.AlgSHA256, pcrValue, ""); err != nil {
			t.Fatalf("failed to extend pcr: %v", err)
		}

		pcrAfter, err := tpm2.ReadPCR(rw, pcr, tpm2.AlgSHA256)
		if err != nil {
			t.Fatalf("failed fetching PCR: %v", err)
		}

		if bytes.Equal(pcrBefore, pcrAfter) {
			t.Fatalf("PCR value didn't change\npcr before: %x\npcr after: %x\n", pcrBefore, pcrAfter)
		}
	})
}
