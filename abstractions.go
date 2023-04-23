package main

import (
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type AuthSession struct {
	rwc            io.ReadWriteCloser
	sessionHandler tpmutil.Handle
}

func (a *AuthSession) StartAuth() error {
	var err error
	a.sessionHandler, _, err = tpm2.StartAuthSession(
		a.rwc,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return err
	}
	return nil
}

func (a *AuthSession) Flush() error {
	return tpm2.FlushContext(a.rwc, a.sessionHandler)
}
