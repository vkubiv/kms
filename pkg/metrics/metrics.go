/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"sync"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "kmsMethods"

	// Crypto.
	crypto               = "crypto"
	cryptoSignTimeMetric = "sign_seconds"

	// DB.
	db                  = "db"
	dbPutTimeMetric     = "put_seconds"
	dbGetTimeMetric     = "get_seconds"
	dbGetTagsTimeMetric = "get_tags_seconds"
	dbGetBulkTimeMetric = "get_bulk_seconds"
	dbQueryTimeMetric   = "query_seconds"
	dbDeleteTimeMetric  = "delete_seconds"
	dbBatchTimeMetric   = "batch_seconds"

	// Key store.
	keyStore                       = "key_store"
	keyStoreResolveTimeMetric      = "resolve_seconds"
	keyStoreGetKeyTimeMetric       = "get_key_seconds"
	awsSecretLockDecryptTimeMetric = "aws_secret_lock_decrypt_seconds"
	keySecretLockDecryptTimeMetric = "key_secret_lock_decrypt_seconds"
	awsSecretLockEncryptTimeMetric = "aws_secret_lock_encrypt_seconds"
	keySecretLockEncryptTimeMetric = "key_secret_lock_encrypt_seconds"

	// Middleware.
	zcap                            = "zcap"
	zcapMiddlewareTimeMetric        = "middleware_seconds"
	zcapCapabilityResolveTimeMetric = "capability_resolve_seconds"
	zcapLoadDocumentTimeMetric      = "load_document_seconds"
	zcapVDRResolveTimeMetric        = "vdr_resolve_seconds"

	// KMS.
	kms                        = "kms"
	kmsMethodTimeMetrics       = "method_seconds"
	kmsCryptoMethodTimeMetrics = "crypto_method_seconds"
)

var logger = log.New("metrics")

var (
	createOnce sync.Once //nolint:gochecknoglobals
	instance   *Metrics  //nolint:gochecknoglobals
)

// Metrics manages the metrics for KMS.
type Metrics struct {
	cryptoSignTime prometheus.Histogram

	dbPutTimes     map[string]prometheus.Histogram
	dbGetTimes     map[string]prometheus.Histogram
	dbGetTagsTimes map[string]prometheus.Histogram
	dbGetBulkTimes map[string]prometheus.Histogram
	dbQueryTimes   map[string]prometheus.Histogram
	dbDeleteTimes  map[string]prometheus.Histogram
	dbBatchTimes   map[string]prometheus.Histogram

	keyStoreResolveTime prometheus.Histogram
	keyStoreGetKeyTime  prometheus.Histogram

	awsSecretLockDecryptTime prometheus.Histogram
	keySecretLockDecryptTime prometheus.Histogram

	awsSecretLockEncryptTime prometheus.Histogram
	keySecretLockEncryptTime prometheus.Histogram

	zcapldTime                  prometheus.Histogram
	zcapldCapabilityResolveTime prometheus.Histogram
	zcapldLoadDocumentTime      prometheus.Histogram
	zcapldVDRResolve            prometheus.Histogram

	kmsMethods    map[string]prometheus.Histogram
	cryptoMethods map[string]prometheus.Histogram
}

// Get returns an KMS metrics provider.
func Get() *Metrics {
	createOnce.Do(func() {
		instance = newMetrics()
	})

	return instance
}

//nolint:funlen
func newMetrics() *Metrics {
	dbTypes := []string{"CouchDB", "MongoDB", "EDV", "Cache"}
	kmsMethods := []string{"Create", "Get", "ExportPubKeyBytes", "CreateAndExportPubKeyBytes", "PubKeyBytesToHandle"}
	cryptoMethods := []string{
		"ComputeMAC", "Decrypt", "DeriveProof", "Encrypt", "Sign", "SignMulti", "UnwrapKey",
		"Verify", "VerifyMAC", "VerifyMulti", "VerifyProof", "WrapKey",
	}

	m := &Metrics{
		cryptoSignTime:              newCryptoSignTime(),
		dbPutTimes:                  newDBPutTime(dbTypes),
		dbGetTimes:                  newDBGetTime(dbTypes),
		dbGetTagsTimes:              newDBGetTagsTime(dbTypes),
		dbGetBulkTimes:              newDBGetBulkTime(dbTypes),
		dbQueryTimes:                newDBQueryTime(dbTypes),
		dbDeleteTimes:               newDBDeleteTime(dbTypes),
		dbBatchTimes:                newDBBatchTime(dbTypes),
		keyStoreResolveTime:         newKeyStoreResolveTime(),
		keyStoreGetKeyTime:          newKeyStoreGetKeyTime(),
		awsSecretLockDecryptTime:    newAWSSecretLockDecryptTime(),
		keySecretLockDecryptTime:    newKeySecretLockDecryptTime(),
		awsSecretLockEncryptTime:    newAWSSecretLockEncryptTime(),
		keySecretLockEncryptTime:    newKeySecretLockEncryptTime(),
		zcapldTime:                  newZCAPMiddlewareTime(),
		zcapldCapabilityResolveTime: newZCAPCapabilityResolveTime(),
		zcapldLoadDocumentTime:      newZCAPLoadDocumentTime(),
		zcapldVDRResolve:            newZCAPVDRResolveTime(),
		kmsMethods:                  newKMSMethodsTime(kmsMethods),
		cryptoMethods:               newCryptoMethodsTime(cryptoMethods),
	}

	prometheus.MustRegister(
		m.cryptoSignTime, m.keyStoreResolveTime, m.keyStoreGetKeyTime, m.awsSecretLockDecryptTime, m.keySecretLockDecryptTime,
		m.awsSecretLockEncryptTime, m.keySecretLockEncryptTime, m.zcapldTime, m.zcapldCapabilityResolveTime,
		m.zcapldLoadDocumentTime, m.zcapldVDRResolve,
	)

	for _, c := range m.dbPutTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbGetTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbGetTagsTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbGetBulkTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbBatchTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbDeleteTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbQueryTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.kmsMethods {
		prometheus.MustRegister(c)
	}

	for _, c := range m.cryptoMethods {
		prometheus.MustRegister(c)
	}

	return m
}

// CryptoSignTime records the time it takes make sign ops.
func (m *Metrics) CryptoSignTime(value time.Duration) {
	m.cryptoSignTime.Observe(value.Seconds())

	logger.Debugf("Sign time: %s", value)
}

// DBPutTime records the time it takes to store data in db.
func (m *Metrics) DBPutTime(dbType string, value time.Duration) {
	if c, ok := m.dbPutTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBGetTime records the time it takes to get data in db.
func (m *Metrics) DBGetTime(dbType string, value time.Duration) {
	if c, ok := m.dbGetTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBGetTagsTime records the time it takes to get tags in db.
func (m *Metrics) DBGetTagsTime(dbType string, value time.Duration) {
	if c, ok := m.dbGetTagsTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBGetBulkTime records the time it takes to get bulk in db.
func (m *Metrics) DBGetBulkTime(dbType string, value time.Duration) {
	if c, ok := m.dbGetBulkTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBQueryTime records the time it takes to query in db.
func (m *Metrics) DBQueryTime(dbType string, value time.Duration) {
	if c, ok := m.dbQueryTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBDeleteTime records the time it takes to delete in db.
func (m *Metrics) DBDeleteTime(dbType string, value time.Duration) {
	if c, ok := m.dbDeleteTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBBatchTime records the time it takes to batch in db.
func (m *Metrics) DBBatchTime(dbType string, value time.Duration) {
	if c, ok := m.dbBatchTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// KeyStoreResolveTime records the time it takes to resolve a key store.
func (m *Metrics) KeyStoreResolveTime(value time.Duration) {
	m.keyStoreResolveTime.Observe(value.Seconds())

	logger.Debugf("KeystoreResolve time: %s", value)
}

// KeyStoreGetKeyTime records the time it takes to get key from a key store.
func (m *Metrics) KeyStoreGetKeyTime(value time.Duration) {
	m.keyStoreGetKeyTime.Observe(value.Seconds())

	logger.Debugf("KeyStoreGetKey time: %s", value)
}

// AWSSecretLockDecryptTime records the time it takes to decrypt key from a key store.
func (m *Metrics) AWSSecretLockDecryptTime(value time.Duration) {
	m.awsSecretLockDecryptTime.Observe(value.Seconds())

	logger.Debugf("AWSSecretLockDecrypt time: %s", value)
}

// KeySecretLockDecryptTime records the time it takes to decrypt key from a key store.
func (m *Metrics) KeySecretLockDecryptTime(value time.Duration) {
	m.keySecretLockDecryptTime.Observe(value.Seconds())

	logger.Debugf("KeySecretLockDecrypt time: %s", value)
}

// AWSSecretLockEncryptTime records the time it takes to encrypt key from a key store.
func (m *Metrics) AWSSecretLockEncryptTime(value time.Duration) {
	m.awsSecretLockEncryptTime.Observe(value.Seconds())

	logger.Debugf("AWSSecretLockEncrypt time: %s", value)
}

// KeySecretLockEncryptTime records the time it takes to encrypt key from a key store.
func (m *Metrics) KeySecretLockEncryptTime(value time.Duration) {
	m.keySecretLockEncryptTime.Observe(value.Seconds())

	logger.Debugf("KeySecretLockEncrypt time: %s", value)
}

// ZCAPLDTime records the time it takes to run zcapld middleware.
func (m *Metrics) ZCAPLDTime(value time.Duration) {
	m.zcapldTime.Observe(value.Seconds())

	logger.Debugf("ZCAPLD time: %s", value)
}

// ZCAPLDCapabilityResolveTime records the time it takes to resolve zcapld capability.
func (m *Metrics) ZCAPLDCapabilityResolveTime(value time.Duration) {
	m.zcapldCapabilityResolveTime.Observe(value.Seconds())

	logger.Debugf("ZCAPLD capability resolve: %s", value)
}

// ZCAPLDLoadDocumentTime records the time it takes to load zcapld document.
func (m *Metrics) ZCAPLDLoadDocumentTime(value time.Duration) {
	m.zcapldLoadDocumentTime.Observe(value.Seconds())

	logger.Debugf("ZCAPLD load document time: %s", value)
}

// ZCAPLDVDRResolveTime records the time it takes to resolve zcapld vdr.
func (m *Metrics) ZCAPLDVDRResolveTime(value time.Duration) {
	m.zcapldVDRResolve.Observe(value.Seconds())

	logger.Debugf("ZCAPLD VDR resolve time: %s", value)
}

// KMSMethodTime records the time it takes to execute a kms method.
func (m *Metrics) KMSMethodTime(method string, value time.Duration) {
	m.kmsMethods[method].Observe(value.Seconds())

	logger.Debugf("KMS %s time: %s", method, value)
}

// CryptoMethodTime records the time it takes to execute a crypto method.
func (m *Metrics) CryptoMethodTime(method string, value time.Duration) {
	m.cryptoMethods[method].Observe(value.Seconds())

	logger.Debugf("Crypto %s time: %s", method, value)
}

func newHistogram(subsystem, name, help string, labels prometheus.Labels) prometheus.Histogram {
	return prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace:   namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	})
}

func newCryptoSignTime() prometheus.Histogram {
	return newHistogram(
		crypto, cryptoSignTimeMetric,
		"The time (in seconds) that it takes to sign message.",
		nil,
	)
}

func newDBPutTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbPutTimeMetric,
			"The time (in seconds) it takes the DB to store data.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBGetTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbGetTimeMetric,
			"The time (in seconds) it takes the DB to get data.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBGetTagsTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbGetTagsTimeMetric,
			"The time (in seconds) it takes the DB to get tags.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBGetBulkTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbGetBulkTimeMetric,
			"The time (in seconds) it takes the DB to get bulk.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBQueryTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbQueryTimeMetric,
			"The time (in seconds) it takes the DB to query.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBDeleteTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbDeleteTimeMetric,
			"The time (in seconds) it takes the DB to delete.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBBatchTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbBatchTimeMetric,
			"The time (in seconds) it takes the DB to batch.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newKeyStoreResolveTime() prometheus.Histogram {
	return newHistogram(
		keyStore, keyStoreResolveTimeMetric,
		"The time (in seconds) that it takes to resolve keystore.",
		nil,
	)
}

func newKeyStoreGetKeyTime() prometheus.Histogram {
	return newHistogram(
		keyStore, keyStoreGetKeyTimeMetric,
		"The time (in seconds) that it takes to get key from keystore.",
		nil,
	)
}

func newAWSSecretLockDecryptTime() prometheus.Histogram {
	return newHistogram(
		keyStore, awsSecretLockDecryptTimeMetric,
		"The time (in seconds) that it takes to decrypt key from keystore.",
		nil,
	)
}

func newKeySecretLockDecryptTime() prometheus.Histogram {
	return newHistogram(
		keyStore, keySecretLockDecryptTimeMetric,
		"The time (in seconds) that it takes to decrypt key from keystore.",
		nil,
	)
}

func newAWSSecretLockEncryptTime() prometheus.Histogram {
	return newHistogram(
		keyStore, awsSecretLockEncryptTimeMetric,
		"The time (in seconds) that it takes to encrypt key from keystore.",
		nil,
	)
}

func newKeySecretLockEncryptTime() prometheus.Histogram {
	return newHistogram(
		keyStore, keySecretLockEncryptTimeMetric,
		"The time (in seconds) that it takes to encrypt key from keystore.",
		nil,
	)
}

func newZCAPMiddlewareTime() prometheus.Histogram {
	return newHistogram(
		zcap, zcapMiddlewareTimeMetric,
		"The time (in seconds) that it takes to run zcap middleware.",
		nil,
	)
}

func newZCAPCapabilityResolveTime() prometheus.Histogram {
	return newHistogram(
		zcap, zcapCapabilityResolveTimeMetric,
		"The time (in seconds) that it takes to resolve capability.",
		nil,
	)
}

func newZCAPLoadDocumentTime() prometheus.Histogram {
	return newHistogram(
		zcap, zcapLoadDocumentTimeMetric,
		"The time (in seconds) that it takes to load zcap document.",
		nil,
	)
}

func newZCAPVDRResolveTime() prometheus.Histogram {
	return newHistogram(
		zcap, zcapVDRResolveTimeMetric,
		"The time (in seconds) that it takes to resolve vdr.",
		nil,
	)
}

func newKMSMethodsTime(methods []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, method := range methods {
		counters[method] = newHistogram(
			kms, kmsMethodTimeMetrics,
			"The time (in seconds) it takes the execute kms method.",
			prometheus.Labels{"type": method},
		)
	}

	return counters
}

func newCryptoMethodsTime(methods []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, method := range methods {
		counters[method] = newHistogram(
			kms, kmsCryptoMethodTimeMetrics,
			"The time (in seconds) it takes the execute kms method.",
			prometheus.Labels{"type": method},
		)
	}

	return counters
}
