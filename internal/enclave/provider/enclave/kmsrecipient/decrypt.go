// Copyright (c) 2026, Circle Internet Group, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package kmsrecipient decrypts the CMS envelope returned by attested AWS KMS
// calls in CiphertextForRecipient.
package kmsrecipient

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
)

var (
	// ErrDecrypt deliberately hides which CMS, RSA, AES, or padding check failed.
	ErrDecrypt = errors.New("decrypt KMS recipient ciphertext")

	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidPSpecified    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 9}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

const (
	envelopedDataVersion = 2
	recipientInfoVersion = 2
	aes256KeySize        = 32
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     envelopedData `asn1:"explicit,tag:0"`
	Extra       asn1.RawValue `asn1:"optional"`
}

type envelopedData struct {
	Version              int
	RecipientInfos       []keyTransRecipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
	Extra                asn1.RawValue `asn1:"optional"`
}

type keyTransRecipientInfo struct {
	Version                int
	RecipientIdentifier    []byte `asn1:"tag:0"`
	KeyEncryptionAlgorithm algorithmIdentifier
	EncryptedKey           []byte
	Extra                  asn1.RawValue `asn1:"optional"`
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
	Extra                      asn1.RawValue `asn1:"optional"`
}

type rsaOAEPParameters struct {
	HashAlgorithm    algorithmIdentifier `asn1:"explicit,optional,tag:0"`
	MaskGenAlgorithm algorithmIdentifier `asn1:"explicit,optional,tag:1"`
	PSourceAlgorithm algorithmIdentifier `asn1:"explicit,optional,tag:2"`
	Extra            asn1.RawValue       `asn1:"optional"`
}

type algorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
	// Parameters consumes the optional second element; Extra captures a third.
	// Algorithm-specific validators must still reject unsupported parameters.
	Parameters asn1.RawValue `asn1:"optional"`
	Extra      asn1.RawValue `asn1:"optional"`
}

type encryptedKey struct {
	rsaCiphertext []byte
	ciphertext    []byte
	iv            []byte
}

// Decrypt unwraps an attested AWS KMS CiphertextForRecipient value. Every
// failure is collapsed to ErrDecrypt so callers cannot distinguish stages.
func Decrypt(privateKey *rsa.PrivateKey, content []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrDecrypt
	}

	envelope, err := parse(content)
	if err != nil {
		return nil, ErrDecrypt
	}
	plaintext, err := envelope.decrypt(privateKey)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

func parse(content []byte) (*encryptedKey, error) {
	der, err := berToDER(content)
	if err != nil {
		return nil, err
	}

	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid CMS content info")
	}
	if hasExtra(ci.Extra) || hasExtra(ci.Content.Extra) ||
		!ci.ContentType.Equal(oidEnvelopedData) || ci.Content.Version != envelopedDataVersion {
		return nil, errors.New("invalid CMS envelope")
	}
	if len(ci.Content.RecipientInfos) != 1 {
		return nil, errors.New("invalid CMS recipient count")
	}

	recipient := ci.Content.RecipientInfos[0]
	if hasExtra(recipient.Extra) || recipient.Version != recipientInfoVersion ||
		len(recipient.RecipientIdentifier) == 0 || len(recipient.EncryptedKey) == 0 {
		return nil, errors.New("invalid CMS recipient")
	}
	if err := validateOAEP(recipient.KeyEncryptionAlgorithm); err != nil {
		return nil, err
	}

	encryptedContent := ci.Content.EncryptedContentInfo
	if hasExtra(encryptedContent.Extra) || hasExtra(encryptedContent.ContentEncryptionAlgorithm.Extra) ||
		!encryptedContent.ContentType.Equal(oidData) ||
		!encryptedContent.ContentEncryptionAlgorithm.Algorithm.Equal(oidAES256CBC) {
		return nil, errors.New("invalid CMS content encryption algorithm")
	}
	iv, err := decodeOctetString(encryptedContent.ContentEncryptionAlgorithm.Parameters)
	if err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("invalid CMS initialization vector")
	}
	ciphertext, err := decodeEncryptedContent(encryptedContent.EncryptedContent)
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("invalid CMS ciphertext")
	}

	return &encryptedKey{
		rsaCiphertext: recipient.EncryptedKey,
		ciphertext:    ciphertext,
		iv:            iv,
	}, nil
}

func validateOAEP(algorithm algorithmIdentifier) error {
	if hasExtra(algorithm.Extra) || !algorithm.Algorithm.Equal(oidRSAESOAEP) || len(algorithm.Parameters.FullBytes) == 0 {
		return errors.New("invalid CMS key encryption algorithm")
	}

	var params rsaOAEPParameters
	rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params)
	if err != nil || len(rest) != 0 || hasExtra(params.Extra) {
		return errors.New("invalid RSA-OAEP parameters")
	}
	if !isSHA256(params.HashAlgorithm) || hasExtra(params.MaskGenAlgorithm.Extra) ||
		!params.MaskGenAlgorithm.Algorithm.Equal(oidMGF1) {
		return errors.New("unsupported RSA-OAEP parameters")
	}
	if !containsSHA256Algorithm(params.MaskGenAlgorithm.Parameters.FullBytes) {
		return errors.New("unsupported RSA-OAEP mask generation function")
	}
	if len(params.PSourceAlgorithm.Algorithm) != 0 && !isEmptyPSpecified(params.PSourceAlgorithm) {
		return errors.New("unsupported RSA-OAEP label")
	}
	return nil
}

func isSHA256(algorithm algorithmIdentifier) bool {
	return !hasExtra(algorithm.Extra) && algorithm.Algorithm.Equal(oidSHA256) && isNullOrAbsent(algorithm.Parameters)
}

func containsSHA256Algorithm(data []byte) bool {
	var algorithm algorithmIdentifier
	rest, err := asn1.Unmarshal(data, &algorithm)
	return err == nil && len(rest) == 0 && isSHA256(algorithm)
}

func isEmptyPSpecified(algorithm algorithmIdentifier) bool {
	if hasExtra(algorithm.Extra) || !algorithm.Algorithm.Equal(oidPSpecified) {
		return false
	}
	value, err := decodeOctetString(algorithm.Parameters)
	return err == nil && len(value) == 0
}

func hasExtra(value asn1.RawValue) bool {
	return len(value.FullBytes) != 0
}

func isNullOrAbsent(value asn1.RawValue) bool {
	return len(value.FullBytes) == 0 ||
		(value.Class == asn1.ClassUniversal && value.Tag == asn1.TagNull && !value.IsCompound && len(value.Bytes) == 0)
}

func decodeOctetString(value asn1.RawValue) ([]byte, error) {
	if value.Class != asn1.ClassUniversal || value.Tag != asn1.TagOctetString || value.IsCompound {
		return nil, errors.New("expected OCTET STRING")
	}
	return bytes.Clone(value.Bytes), nil
}

func decodeEncryptedContent(value asn1.RawValue) ([]byte, error) {
	if value.Class != asn1.ClassContextSpecific || value.Tag != 0 {
		return nil, errors.New("invalid encrypted content tag")
	}
	if !value.IsCompound {
		return bytes.Clone(value.Bytes), nil
	}

	remaining := value.Bytes
	var ciphertext []byte
	for len(remaining) > 0 {
		var part []byte
		rest, err := asn1.Unmarshal(remaining, &part)
		if err != nil || len(rest) >= len(remaining) {
			return nil, errors.New("invalid encrypted content fragment")
		}
		ciphertext = append(ciphertext, part...)
		remaining = rest
	}
	return ciphertext, nil
}

// decrypt returns stage-specific errors and does not normalize execution time.
// Keep it package-internal; Decrypt is the boundary that collapses failures.
func (e *encryptedKey) decrypt(privateKey *rsa.PrivateKey) ([]byte, error) {
	contentKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, e.rsaCiphertext, nil)
	if err != nil {
		return nil, err
	}
	defer clear(contentKey)
	if len(contentKey) != aes256KeySize {
		return nil, errors.New("invalid AES-256 content key")
	}

	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	if len(e.iv) != block.BlockSize() || len(e.ciphertext) == 0 || len(e.ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("invalid AES-CBC parameters")
	}

	plaintext := make([]byte, len(e.ciphertext))
	cipher.NewCBCDecrypter(block, e.iv).CryptBlocks(plaintext, e.ciphertext)
	unpadded, err := unpadPKCS7(plaintext, block.BlockSize())
	if err != nil {
		clear(plaintext)
		return nil, err
	}
	return unpadded, nil
}

func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid PKCS#7 input")
	}

	paddingLength := int(data[len(data)-1])
	valid := subtle.ConstantTimeLessOrEq(1, paddingLength) & subtle.ConstantTimeLessOrEq(paddingLength, blockSize)
	for i := 0; i < blockSize; i++ {
		inPadding := subtle.ConstantTimeLessOrEq(i+1, paddingLength)
		matches := subtle.ConstantTimeByteEq(data[len(data)-1-i], byte(paddingLength))
		valid &= subtle.ConstantTimeSelect(inPadding, matches, 1)
	}
	if valid != 1 {
		return nil, errors.New("invalid PKCS#7 padding")
	}
	return data[:len(data)-paddingLength], nil
}
