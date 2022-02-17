package metrics

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"

	"github.com/trustbloc/kms/pkg/metrics"
)

// wrappedCrypto implements crypto.Crypto interface with all methods wrapped
// with Prometheus metrics.
type wrappedCrypto struct {
	base crypto.Crypto
}

// WrapCrypto returns an instance of the crypto.Crypto decorated with prometheus metrics.
func WrapCrypto(base crypto.Crypto) crypto.Crypto {
	return &wrappedCrypto{
		base: base,
	}
}

// ComputeMAC implements crypto.Crypto.
func (w *wrappedCrypto) ComputeMAC(data []byte, kh interface{}) ([]byte, error) {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("ComputeMAC", time.Since(getStartTime))
	}()

	return w.base.ComputeMAC(data, kh)
}

// Decrypt implements crypto.Crypto.
func (w *wrappedCrypto) Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error) {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("Decrypt", time.Since(getStartTime))
	}()

	return w.base.Decrypt(cipher, aad, nonce, kh)
}

// DeriveProof implements crypto.Crypto.
func (w *wrappedCrypto) DeriveProof(messages [][]byte,
	bbsSignature, nonce []byte, revealedIndexes []int, kh interface{}) ([]byte, error) {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("DeriveProof", time.Since(getStartTime))
	}()

	return w.base.DeriveProof(messages, bbsSignature, nonce, revealedIndexes, kh)
}

// Encrypt implements crypto.Crypto.
func (w *wrappedCrypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("Encrypt", time.Since(getStartTime))
	}()

	return w.base.Encrypt(msg, aad, kh)
}

// Sign implements crypto.Crypto.
func (w *wrappedCrypto) Sign(msg []byte, kh interface{}) ([]byte, error) {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("Sign", time.Since(getStartTime))
	}()

	return w.base.Sign(msg, kh)
}

// SignMulti implements crypto.Crypto.
func (w *wrappedCrypto) SignMulti(messages [][]byte, kh interface{}) ([]byte, error) {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("SignMulti", time.Since(getStartTime))
	}()

	return w.base.SignMulti(messages, kh)
}

// UnwrapKey implements crypto.Crypto.
func (w *wrappedCrypto) UnwrapKey(recWK *crypto.RecipientWrappedKey,
	kh interface{}, opts ...crypto.WrapKeyOpts) ([]byte, error) {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("UnwrapKey", time.Since(getStartTime))
	}()

	return w.base.UnwrapKey(recWK, kh, opts...)
}

// Verify implements crypto.Crypto.
func (w *wrappedCrypto) Verify(signature, msg []byte, kh interface{}) error {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("Verify", time.Since(getStartTime))
	}()

	return w.base.Verify(signature, msg, kh)
}

// VerifyMAC implements crypto.Crypto.
func (w *wrappedCrypto) VerifyMAC(mac, data []byte, kh interface{}) error {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("VerifyMAC", time.Since(getStartTime))
	}()

	return w.base.VerifyMAC(mac, data, kh)
}

// VerifyMulti implements crypto.Crypto.
func (w *wrappedCrypto) VerifyMulti(messages [][]byte, signature []byte, kh interface{}) error {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("VerifyMulti", time.Since(getStartTime))
	}()

	return w.base.VerifyMulti(messages, signature, kh)
}

// VerifyProof implements crypto.Crypto.
func (w *wrappedCrypto) VerifyProof(revealedMessages [][]byte, proof, nonce []byte, kh interface{}) error {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("VerifyProof", time.Since(getStartTime))
	}()

	return w.base.VerifyProof(revealedMessages, proof, nonce, kh)
}

// WrapKey implements crypto.Crypto.
func (w *wrappedCrypto) WrapKey(cek []byte, apu []byte,
	apv []byte, recPubKey *crypto.PublicKey, opts ...crypto.WrapKeyOpts) (*crypto.RecipientWrappedKey, error) {
	getStartTime := time.Now()
	defer func() {
		metrics.Get().CryptoMethodTime("WrapKey", time.Since(getStartTime))
	}()

	return w.base.WrapKey(cek, apu, apv, recPubKey, opts...)
}
