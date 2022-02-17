/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

//go:generate mockgen -destination gomocks_test.go -package metrics_test . KeyManager

import (
	"time"

	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/kms/pkg/metrics"
)

// KeyManager is an alias for arieskms.KeyManager.
type KeyManager = arieskms.KeyManager

type wrappedKMS struct {
	kms KeyManager
}

// WrapKMS adds metrics support to the underlying KeyManager.
func WrapKMS(kms KeyManager) KeyManager {
	return &wrappedKMS{
		kms: kms,
	}
}

func (w *wrappedKMS) Create(kt arieskms.KeyType) (string, interface{}, error) {
	getStartTime := time.Now()

	keyID, kh, err := w.kms.Create(kt)

	metrics.Get().KMSMethodTime("Create", time.Since(getStartTime))

	return keyID, kh, err
}

func (w *wrappedKMS) Get(keyID string) (interface{}, error) {
	getStartTime := time.Now()

	kh, err := w.kms.Get(keyID)

	metrics.Get().KMSMethodTime("Get", time.Since(getStartTime))

	return kh, err
}

func (w *wrappedKMS) Rotate(kt arieskms.KeyType, keyID string) (string, interface{}, error) {
	return w.kms.Rotate(kt, keyID)
}

func (w *wrappedKMS) ExportPubKeyBytes(keyID string) ([]byte, error) {
	getStartTime := time.Now()

	pubKeyBytes, err := w.kms.ExportPubKeyBytes(keyID)

	metrics.Get().KMSMethodTime("ExportPubKeyBytes", time.Since(getStartTime))

	return pubKeyBytes, err
}

func (w *wrappedKMS) CreateAndExportPubKeyBytes(kt arieskms.KeyType) (string, []byte, error) {
	getStartTime := time.Now()

	keyID, pubKeyBytes, err := w.kms.CreateAndExportPubKeyBytes(kt)

	metrics.Get().KMSMethodTime("CreateAndExportPubKeyBytes", time.Since(getStartTime))

	return keyID, pubKeyBytes, err
}

func (w *wrappedKMS) PubKeyBytesToHandle(pubKey []byte, kt arieskms.KeyType) (interface{}, error) {
	getStartTime := time.Now()

	kh, err := w.kms.PubKeyBytesToHandle(pubKey, kt)

	metrics.Get().KMSMethodTime("PubKeyBytesToHandle", time.Since(getStartTime))

	return kh, err
}

func (w *wrappedKMS) ImportPrivateKey(privateKey interface{}, kt arieskms.KeyType,
	opts ...arieskms.PrivateKeyOpts) (string, interface{}, error) {
	return w.kms.ImportPrivateKey(privateKey, kt, opts...)
}
