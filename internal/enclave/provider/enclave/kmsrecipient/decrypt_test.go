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

package kmsrecipient

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fixture was produced by AWS KMS and published with the Apache-2.0
// Edgebit Nitro Enclaves SDK for Go compatibility test.
const testPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwg8xlWTIwm44aLEqiA5lweHUSm2eeKwrTg3qEUhOVyGAo3eN
XRoD9wOHzjcvS8r/qfQdSdLA9p6IbSxV9LU2fXgYnT3IDhNuQ1rVkiIYqWqPWUn2
izUMJmbdVFRsgWi7/keXkslZD0DeKQM1R2QsCRZnPGHU3Jo/+2b6dTg8IRoBH2cq
rAPuynqBXYCC9+wNdYMQLA5vdaVzhFBASIVkMDDWlMaFgdOsISMHy9Klm0cXj3RE
02VsHcOQ1NRLY4Ddgpb5r0LUB0nfB4HMeK9plYqkkVF5BJihoGtGmebGuMqSFNgU
XflrxH152bHAZqqV+aIPIy2y4IdaQgP1VJrVKwIDAQABAoIBAQCQhtJNyh6+t2np
hrD/XYGpkPATcmqIwukJm9FMh8ZYnAn7NKmiwiJb0FRPX8gosYoRYE6D0aOGyPEg
Jdnqgx+O+GeUjBO3b/85yKewyxYE7ujN/gjRCnP/EbMbADlDc+Y27cjUOILMmmoa
r1n5zoABUJ8YWGA43+Rw7vPvYy9dEn1fbmsp850u/Grqdi0MUwIpQe9VKkVsYZ0n
HKAz+uY9Mhb/CsveD75cHrpaa5Ilfjkzo47Gah/+E6LB3/5wRjlzNzLMAQT449PW
yt2E/DYtVAR8uAtbfHB3cFcgNrWVg9IwU1G74SwqqwgQfpfEqKqsqG9BBXz0vwLT
o3vczVWZAoGBANJbz5+1XRlblmDV8MnVGoaHoylIA6+xE5iTiAUtopxfh3lMgTAh
sIepf7na0nkNPXFrR48Tkm29Y4f8EU2LY0a1t9WyAyufz9UTA4ABlHCuKztSqpG7
SgGEQvr/bAE61uN7JwVXGUICAR27OVfy7+iIOCzFDaOwhyfrE2XuP82VAoGBAOwq
DYedgoxuV63BWYDtvUt4olQbBCczJKyDirTGGdiPyQbsfE5eegcfZYxRkiCJ0Z5z
9OQlafIrok93kwkWgta2dj3onbXKLUviyGMSW1kGXoaTZu47rTZ7nxhqS5QeySGl
sHs/8j3+2UPHnwvLMlrMAOhIFQYrlFeQkxvIw+e/AoGAZh2Xjon2JccmGuAAQZon
hEL326RP1cv6HUkQ8KKUm6BsHWAcHodcMJ8Bl/E31vesahCP7k6r+IXFeU/N/ny5
tqukECKYE2dC9saCHnOl4YVLC0M39gKbDF1uPnYbsgUkJ82yxY7gfgCHFi26yozu
FU17J5CI7HtXQPOGuSaM5nkCgYEAqI4PIAbMYVxz2cDRF9MWsuIDwdGSckPvXe14
tzNYyRc+nGF3CxwlLiY7fR3PFMgow1XxqFAHwN9htiQa3nahpYuO8vqubUxCbhIL
gaJdbjm8h4J3CXuwUd2DnJJpJOugFBLE1gK664KUIOs92dYKN4G4+BBSaRf7hU/b
nw34vNMCgYBfG/VbQXT1WCcJgVycnU1hX7zmyzB/hk0xkmLR0nUzTgXMKOKUUXgX
2mD7U5VGZPYj7t8P+bz6/HEZqKmOoxFkXpsMPug34ZUWfjv3uCm7CFHtxA+BDT+5
cJEGAbCDYhyjvtjBLNy7YDQ1hdmCnqMxg/5AIwUMkvTTRg+qepfboA==
-----END RSA PRIVATE KEY-----`

const testCiphertextForRecipient = `MIAGCSqGSIb3DQEHA6CAMIACAQIxggFrMIIBZwIBAoAgljGgxlmRCtWqvB/s/Aw+ZNTDlc6Uka86SLVmlNmFGAMwPAYJKoZIhvcNAQEHMC+gDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAASCAQAXmjTiHpg+OcYaf2ISaDNpQcEOq61Sm3re3v+5z2hZPe8eoUGhmMS6pCuC+BRW7RpkjwDaXQzzR/jExnraEET3lj9oyAMMwKIahhHHIZ33qOTq1c/9NtMVZmm/j4UfyCpP8WMAFb2hvwIJbjnAGO9Xbw+NzWaQdvEyNDGUX+bPIuSDc75jjGH5KtdFLopk5k6nsTdU26qLkVE6Mg9Y//s0OJCvmYFgfw15IXDb50xJupWxCwbqGXWmfTBEo9M9AhelVbOXkitZR7hbnT6BZnsfpS2acZRNL4XxC+gg4Ml9fOiYsGWqSK8Lkwlp22rtL70CIHnggbb+oIE4ObR4TV8qMIAGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEEMr/6uiZK+CzgfJvr61JTGggAQwfp0W0Q/QPYmg6AoC3DkE5+beNswVOX9ct5IIgIsvaAhTF9IiHdbX7yLa8YS2WQ/FAAAAAAAAAAAAAA==`

func TestDecrypt_ValidKMSFixture(t *testing.T) {
	privateKey := decodeTestPrivateKey(t)
	ciphertext, err := base64.StdEncoding.DecodeString(testCiphertextForRecipient)
	require.NoError(t, err)

	got, err := Decrypt(privateKey, ciphertext)

	require.NoError(t, err)
	require.Equal(t, []byte{
		0x3b, 0xe8, 0x2c, 0x44, 0x0f, 0x06, 0xcb, 0x4d,
		0x44, 0xc4, 0xc2, 0xec, 0x3b, 0xf3, 0x0d, 0x47,
		0x24, 0x07, 0xd3, 0xa9, 0x12, 0x5a, 0xa4, 0xc1,
		0x84, 0x2b, 0x98, 0xf6, 0xbd, 0xd2, 0x6e, 0x41,
	}, got)
}

func TestDecrypt_InvalidInputsReturnStableError(t *testing.T) {
	privateKey := decodeTestPrivateKey(t)
	validCiphertext, err := base64.StdEncoding.DecodeString(testCiphertextForRecipient)
	require.NoError(t, err)
	wrongPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	parsed, err := parse(validCiphertext)
	require.NoError(t, err)
	ciphertextOffset := bytes.Index(validCiphertext, parsed.ciphertext)
	require.NotEqual(t, -1, ciphertextOffset)
	badPadding := bytes.Clone(validCiphertext)
	badPadding[ciphertextOffset+len(parsed.ciphertext)-1] ^= 0xff

	tests := []struct {
		name       string
		privateKey *rsa.PrivateKey
		ciphertext []byte
	}{
		{name: "nil private key", ciphertext: validCiphertext},
		{name: "empty CMS", privateKey: privateKey},
		{name: "truncated CMS", privateKey: privateKey, ciphertext: validCiphertext[:len(validCiphertext)-1]},
		{name: "trailing CMS data", privateKey: privateKey, ciphertext: append(bytes.Clone(validCiphertext), 0x00)},
		{name: "RSA failure", privateKey: wrongPrivateKey, ciphertext: validCiphertext},
		{name: "padding failure", privateKey: privateKey, ciphertext: badPadding},
		{name: "oversized CMS", privateKey: privateKey, ciphertext: make([]byte, maxBERSize+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := Decrypt(tt.privateKey, tt.ciphertext)

			require.Nil(t, got)
			require.ErrorIs(t, gotErr, ErrDecrypt)
			require.Equal(t, ErrDecrypt.Error(), gotErr.Error())
		})
	}
}

func TestDecrypt_TruncatedCMSNeverPanics(t *testing.T) {
	privateKey := decodeTestPrivateKey(t)
	validCiphertext, err := base64.StdEncoding.DecodeString(testCiphertextForRecipient)
	require.NoError(t, err)

	for length := range validCiphertext {
		got, gotErr := Decrypt(privateKey, validCiphertext[:length])

		require.Nil(t, got)
		require.ErrorIs(t, gotErr, ErrDecrypt)
	}
}

func TestDecrypt_RejectsUnexpectedTopLevelField(t *testing.T) {
	privateKey := decodeTestPrivateKey(t)
	validCiphertext, err := base64.StdEncoding.DecodeString(testCiphertextForRecipient)
	require.NoError(t, err)
	der, err := berToDER(validCiphertext)
	require.NoError(t, err)
	var topLevel asn1.RawValue
	rest, err := asn1.Unmarshal(der, &topLevel)
	require.NoError(t, err)
	require.Empty(t, rest)
	malformed, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(bytes.Clone(topLevel.Bytes), 0x05, 0x00),
	})
	require.NoError(t, err)

	got, err := Decrypt(privateKey, malformed)

	require.ErrorIs(t, err, ErrDecrypt)
	require.Nil(t, got)
}

func TestDecrypt_RejectsUnexpectedNestedFields(t *testing.T) {
	privateKey := decodeTestPrivateKey(t)
	validCiphertext, err := base64.StdEncoding.DecodeString(testCiphertextForRecipient)
	require.NoError(t, err)
	der, err := berToDER(validCiphertext)
	require.NoError(t, err)
	extra := asn1.RawValue{FullBytes: []byte{0x05, 0x00}}
	tests := []struct {
		name   string
		mutate func(*contentInfo)
	}{
		{name: "enveloped data", mutate: func(ci *contentInfo) { ci.Content.Extra = extra }},
		{name: "recipient", mutate: func(ci *contentInfo) { ci.Content.RecipientInfos[0].Extra = extra }},
		{name: "key algorithm", mutate: func(ci *contentInfo) { ci.Content.RecipientInfos[0].KeyEncryptionAlgorithm.Extra = extra }},
		{name: "encrypted content info", mutate: func(ci *contentInfo) { ci.Content.EncryptedContentInfo.Extra = extra }},
		{name: "content algorithm", mutate: func(ci *contentInfo) { ci.Content.EncryptedContentInfo.ContentEncryptionAlgorithm.Extra = extra }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var envelope contentInfo
			rest, err := asn1.Unmarshal(der, &envelope)
			require.NoError(t, err)
			require.Empty(t, rest)
			tt.mutate(&envelope)
			malformed, err := asn1.Marshal(envelope)
			require.NoError(t, err)

			got, err := Decrypt(privateKey, malformed)

			require.ErrorIs(t, err, ErrDecrypt)
			require.Nil(t, got)
		})
	}
}

func TestDecrypt_RejectsUnexpectedMaskGenAlgorithmField(t *testing.T) {
	privateKey := decodeTestPrivateKey(t)
	validCiphertext, err := base64.StdEncoding.DecodeString(testCiphertextForRecipient)
	require.NoError(t, err)
	der, err := berToDER(validCiphertext)
	require.NoError(t, err)

	var envelope contentInfo
	rest, err := asn1.Unmarshal(der, &envelope)
	require.NoError(t, err)
	require.Empty(t, rest)

	var params rsaOAEPParameters
	rest, err = asn1.Unmarshal(
		envelope.Content.RecipientInfos[0].KeyEncryptionAlgorithm.Parameters.FullBytes,
		&params,
	)
	require.NoError(t, err)
	require.Empty(t, rest)
	params.MaskGenAlgorithm.Extra = asn1.RawValue{FullBytes: []byte{0x05, 0x00}}
	paramsDER, err := asn1.Marshal(params)
	require.NoError(t, err)
	envelope.Content.RecipientInfos[0].KeyEncryptionAlgorithm.Parameters = asn1.RawValue{FullBytes: paramsDER}
	malformed, err := asn1.Marshal(envelope)
	require.NoError(t, err)

	got, err := Decrypt(privateKey, malformed)

	require.ErrorIs(t, err, ErrDecrypt)
	require.Nil(t, got)
}

func TestDecrypt_ConstructedEncryptedContent(t *testing.T) {
	privateKey := decodeTestPrivateKey(t)
	validCiphertext, err := base64.StdEncoding.DecodeString(testCiphertextForRecipient)
	require.NoError(t, err)

	tests := []struct {
		name          string
		mutateContent func(*testing.T, []byte) []byte
		wantErr       error
	}{
		{
			name: "reassembles octet string fragments",
			mutateContent: func(t *testing.T, ciphertext []byte) []byte {
				t.Helper()
				midpoint := len(ciphertext) / 2
				return marshalConstructedEncryptedContent(t, ciphertext[:midpoint], ciphertext[midpoint:])
			},
		},
		{
			name: "rejects malformed octet string fragment",
			mutateContent: func(t *testing.T, ciphertext []byte) []byte {
				t.Helper()
				validFragment, err := asn1.Marshal(ciphertext[:aes.BlockSize])
				require.NoError(t, err)
				return marshalRawConstructedEncryptedContent(validFragment, []byte{0x04, 0x02, 0x01})
			},
			wantErr: ErrDecrypt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := rewriteEncryptedContent(t, validCiphertext, func(ciphertext []byte) asn1.RawValue {
				return asn1.RawValue{FullBytes: tt.mutateContent(t, ciphertext)}
			})

			got, err := Decrypt(privateKey, mutated)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, []byte{
				0x3b, 0xe8, 0x2c, 0x44, 0x0f, 0x06, 0xcb, 0x4d,
				0x44, 0xc4, 0xc2, 0xec, 0x3b, 0xf3, 0x0d, 0x47,
				0x24, 0x07, 0xd3, 0xa9, 0x12, 0x5a, 0xa4, 0xc1,
				0x84, 0x2b, 0x98, 0xf6, 0xbd, 0xd2, 0x6e, 0x41,
			}, got)
		})
	}
}

func TestUnpadPKCS7(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []byte
		wantErr bool
	}{
		{name: "full block", data: bytes.Repeat([]byte{0x10}, aesBlockSize), want: []byte{}},
		{name: "one byte", data: append(bytes.Repeat([]byte{0x2a}, aesBlockSize-1), 0x01), want: bytes.Repeat([]byte{0x2a}, aesBlockSize-1)},
		{name: "zero length padding", data: append(bytes.Repeat([]byte{0x2a}, aesBlockSize-1), 0x00), wantErr: true},
		{name: "padding exceeds block", data: append(bytes.Repeat([]byte{0x2a}, aesBlockSize-1), 0x11), wantErr: true},
		{name: "inconsistent padding", data: append(bytes.Repeat([]byte{0x2a}, aesBlockSize-2), 0x01, 0x02), wantErr: true},
		{name: "empty input", wantErr: true},
		{name: "partial block", data: []byte{0x01}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unpadPKCS7(tt.data, aesBlockSize)

			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestEncryptedKeyDecrypt_RejectsNonAES256ContentKey(t *testing.T) {
	privateKey := decodeTestPrivateKey(t)
	contentKey := bytes.Repeat([]byte{0x42}, 16)
	rsaCiphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, contentKey, nil)
	require.NoError(t, err)
	block, err := aes.NewCipher(contentKey)
	require.NoError(t, err)
	iv := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, bytes.Repeat([]byte{aes.BlockSize}, aes.BlockSize))

	got, err := (&encryptedKey{
		rsaCiphertext: rsaCiphertext,
		ciphertext:    ciphertext,
		iv:            iv,
	}).decrypt(privateKey)

	require.Error(t, err)
	require.Nil(t, got)
}

func TestValidateOAEP_PSpecifiedLabel(t *testing.T) {
	tests := []struct {
		name    string
		oid     asn1.ObjectIdentifier
		label   []byte
		wantErr bool
	}{
		{name: "explicit empty default", oid: oidPSpecified},
		{name: "non-empty label", oid: oidPSpecified, label: []byte("label"), wantErr: true},
		{name: "unexpected algorithm", oid: oidSHA256, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algorithm := buildTestOAEPAlgorithm(t, tt.oid, tt.label)

			err := validateOAEP(algorithm)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateOAEP_RejectsExtraParameterField(t *testing.T) {
	algorithm := buildTestOAEPAlgorithm(t, oidPSpecified, nil)
	var params rsaOAEPParameters
	rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params)
	require.NoError(t, err)
	require.Empty(t, rest)
	params.Extra = asn1.RawValue{FullBytes: []byte{0x05, 0x00}}
	paramsDER, err := asn1.Marshal(params)
	require.NoError(t, err)
	algorithm.Parameters = asn1.RawValue{FullBytes: paramsDER}

	err = validateOAEP(algorithm)

	require.Error(t, err)
}

func TestDecodeEncryptedContent_Primitive(t *testing.T) {
	got, err := decodeEncryptedContent(asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   0,
		Bytes: []byte{0x01, 0x02, 0x03},
	})

	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, got)
}

func TestDecodeEncryptedContent_Constructed(t *testing.T) {
	first, err := asn1.Marshal([]byte{0x01, 0x02})
	require.NoError(t, err)
	second, err := asn1.Marshal([]byte{0x03, 0x04})
	require.NoError(t, err)

	got, err := decodeEncryptedContent(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      append(first, second...),
	})

	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, got)
}

func TestDecodeEncryptedContent_RejectsMalformedFragment(t *testing.T) {
	got, err := decodeEncryptedContent(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      []byte{0x04, 0x02, 0x01},
	})

	require.Error(t, err)
	require.Nil(t, got)
}

func TestBERToDER_RejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "unterminated indefinite object", input: []byte{0x30, 0x80, 0x02, 0x01, 0x01}},
		{name: "indefinite primitive", input: []byte{0x04, 0x80, 0x00, 0x00}},
		{name: "truncated high tag", input: []byte{0x1f, 0x81}},
		{name: "non-minimal high tag", input: []byte{0x1f, 0x80, 0x01, 0x00}},
		{name: "long tag", input: []byte{0x1f, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00}},
		{name: "truncated length", input: []byte{0x04}},
		{name: "non-minimal long length", input: []byte{0x04, 0x81, 0x01, 0x00}},
		{name: "leading-zero long length", input: []byte{0x04, 0x82, 0x00, 0x80}},
		{name: "truncated primitive", input: []byte{0x04, 0x02, 0x01}},
		{name: "unexpected end-of-contents", input: []byte{0x30, 0x02, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := berToDER(tt.input)

			require.Error(t, err)
			require.Nil(t, got)
		})
	}
}

func TestBERToDER_MaximumOutputSize(t *testing.T) {
	der, err := berToDER(maxSizeBERObject())

	require.NoError(t, err)
	require.Len(t, der, maxDERObjectSize())
}

func FuzzDecrypt(f *testing.F) {
	privateKey := decodeTestPrivateKey(f)
	validCiphertext, err := base64.StdEncoding.DecodeString(testCiphertextForRecipient)
	require.NoError(f, err)
	f.Add(validCiphertext)
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		plaintext, err := Decrypt(privateKey, ciphertext)
		if err != nil {
			require.ErrorIs(t, err, ErrDecrypt)
			require.Nil(t, plaintext)
		}
	})
}

func FuzzBERToDER(f *testing.F) {
	f.Add([]byte{0x02, 0x01, 0x01})
	f.Add([]byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00})
	f.Add([]byte{})
	f.Add(maxSizeBERObject())

	f.Fuzz(func(t *testing.T, input []byte) {
		der, err := berToDER(input)
		if err == nil {
			require.NotEmpty(t, der)
			require.LessOrEqual(t, len(der), maxDERObjectSize())
		}
	})
}

func maxDERObjectSize() int {
	return maxBERSize + maxBERTagSize + len(appendDERLength(nil, maxBERSize))
}

func maxSizeBERObject() []byte {
	// Each nested indefinite object adds one byte when converted to DER, which
	// offsets the maximum-size outer tag, indefinite length, and EOC marker.
	const nestedConstructedObjects = maxBERTagSize + 3

	input := make([]byte, 0, maxBERSize)
	input = append(input, 0x3f)
	input = append(input, bytes.Repeat([]byte{0x81}, maxBERTagSize-2)...)
	input = append(input, 0x01, 0x80)
	for range nestedConstructedObjects {
		input = append(input, 0x30, 0x80)
	}

	const primitiveHeaderSize = 5
	eocSize := 2 * (nestedConstructedObjects + 1)
	payloadSize := maxBERSize - len(input) - primitiveHeaderSize - eocSize
	input = append(input, 0x04, 0x83, byte(payloadSize>>16), byte(payloadSize>>8), byte(payloadSize))
	input = append(input, make([]byte, payloadSize)...)
	input = append(input, make([]byte, eocSize)...)
	return input
}

func rewriteEncryptedContent(t *testing.T, ciphertext []byte, mutate func([]byte) asn1.RawValue) []byte {
	t.Helper()

	der, err := berToDER(ciphertext)
	require.NoError(t, err)

	var envelope contentInfo
	rest, err := asn1.Unmarshal(der, &envelope)
	require.NoError(t, err)
	require.Empty(t, rest)

	decodedCiphertext, err := decodeEncryptedContent(
		envelope.Content.EncryptedContentInfo.EncryptedContent,
	)
	require.NoError(t, err)

	envelope.Content.EncryptedContentInfo.EncryptedContent = mutate(
		decodedCiphertext,
	)
	mutated, err := asn1.Marshal(envelope)
	require.NoError(t, err)
	return mutated
}

func marshalConstructedEncryptedContent(t *testing.T, fragments ...[]byte) []byte {
	t.Helper()

	rawFragments := make([][]byte, 0, len(fragments))
	for _, fragment := range fragments {
		raw, err := asn1.Marshal(fragment)
		require.NoError(t, err)
		rawFragments = append(rawFragments, raw)
	}
	return marshalRawConstructedEncryptedContent(rawFragments...)
}

func marshalRawConstructedEncryptedContent(fragments ...[]byte) []byte {
	content := bytes.Join(fragments, nil)
	encoded := []byte{0xa0}
	encoded = appendDERLength(encoded, len(content))
	encoded = append(encoded, content...)
	return encoded
}

func decodeTestPrivateKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(testPrivateKeyPEM))
	require.NotNil(t, block)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key
}

func buildTestOAEPAlgorithm(t testing.TB, pSourceOID asn1.ObjectIdentifier, label []byte) algorithmIdentifier {
	t.Helper()
	null := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNull}
	hash := algorithmIdentifier{Algorithm: oidSHA256, Parameters: null}
	hashDER, err := asn1.Marshal(hash)
	require.NoError(t, err)
	labelDER, err := asn1.Marshal(label)
	require.NoError(t, err)
	paramsDER, err := asn1.Marshal(rsaOAEPParameters{
		HashAlgorithm:    hash,
		MaskGenAlgorithm: algorithmIdentifier{Algorithm: oidMGF1, Parameters: asn1.RawValue{FullBytes: hashDER}},
		PSourceAlgorithm: algorithmIdentifier{Algorithm: pSourceOID, Parameters: asn1.RawValue{FullBytes: labelDER}},
	})
	require.NoError(t, err)
	return algorithmIdentifier{
		Algorithm:  oidRSAESOAEP,
		Parameters: asn1.RawValue{FullBytes: paramsDER},
	}
}

const aesBlockSize = 16
