package extract

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" // #nosec G505 -- fixture for protocol-mandated ECMA-376 Standard verification
	"crypto/sha512"
	"encoding/binary"
	"testing"
)

func encryptCBCForDefaultPWTest(t testing.TB, plaintext, key, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(plaintext)%aes.BlockSize != 0 {
		t.Fatalf("plaintext length %d is not block aligned", len(plaintext))
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return out
}

func agileReuseFixture(t testing.TB) (string, agileInfo, []byte) {
	t.Helper()
	password := "reuse-control"
	salt := []byte{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f}
	info := agileInfo{
		passwordSalt:     salt,
		passwordKeyBits:  256,
		spinCount:        1000,
		keyDataSalt:      bytes.Repeat([]byte{0x5a}, 16),
		keyDataBlockSize: aes.BlockSize,
	}
	h := agileHashIter(password, salt, info.spinCount)
	verifier := []byte("agile-verifier!!")
	verifierHash := sha512.Sum512(verifier)
	info.encVerifierHashInput = encryptCBCForDefaultPWTest(t, verifier,
		agileHashFinal(h, agileBlkKeyVerifierHashInput, info.passwordKeyBits), salt)
	info.encVerifierHashValue = encryptCBCForDefaultPWTest(t, verifierHash[:],
		agileHashFinal(h, agileBlkKeyVerifierHashValue, info.passwordKeyBits), salt)
	secret := bytes.Repeat([]byte{0xa5}, info.passwordKeyBits/8)
	info.encKeyValue = encryptCBCForDefaultPWTest(t, secret,
		agileHashFinal(h, agileBlkKeyEncryptedKeyValue, info.passwordKeyBits), salt)
	return password, info, secret
}

func standardReuseFixture(t testing.TB) (string, standardInfo, []byte, []byte) {
	t.Helper()
	password := "reuse-control"
	info := standardInfo{
		salt:    []byte{0xef, 0xde, 0xcd, 0xbc, 0xab, 0x9a, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23, 0x12, 0x01, 0xf0},
		keySize: 128,
	}
	key := standardMakeKey(password, info)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier := []byte("standard-verifer")
	info.encVerifier = make([]byte, aes.BlockSize)
	block.Encrypt(info.encVerifier, verifier)
	verifierHash := sha1.Sum(verifier) //nolint:gosec // protocol fixture
	info.encVerifierHash = make([]byte, 2*aes.BlockSize)
	block.Encrypt(info.encVerifierHash, verifierHash[:aes.BlockSize])

	plain := []byte("standard payload")
	ciphertext := make([]byte, aes.BlockSize)
	block.Encrypt(ciphertext, plain)
	encPkg := make([]byte, 8+len(ciphertext))
	binary.LittleEndian.PutUint32(encPkg, uint32(len(plain)))
	copy(encPkg[8:], ciphertext)
	return password, info, key, encPkg
}

func TestAgileDerivedHashReusePreservesVerificationAndExtraction(t *testing.T) {
	password, info, wantKey := agileReuseFixture(t)
	h := agilePasswordHash(password, info)
	if h == nil {
		t.Fatal("valid Agile parameters did not derive a password hash")
	}
	if !agileVerifyHash(h, info) {
		t.Fatal("derived hash rejected the valid Agile verifier")
	}
	if got := agileExtractKeyFromHash(h, info); !bytes.Equal(got, wantKey) {
		t.Fatalf("reused hash extracted key %x, want %x", got, wantKey)
	}
	if got := agileExtractKey(password, info); !bytes.Equal(got, wantKey) {
		t.Fatalf("compatibility wrapper extracted key %x, want %x", got, wantKey)
	}

	mutated := append([]byte(nil), h...)
	mutated[0] ^= 0xff
	if agileVerifyHash(mutated, info) {
		t.Fatal("mutated Agile password hash passed verification")
	}
	for _, bits := range []int{0, 513} {
		invalid := info
		invalid.passwordKeyBits = bits
		if agilePasswordHash(password, invalid) != nil {
			t.Fatalf("invalid Agile key width %d derived a hash", bits)
		}
		if agileVerifyHash(h, invalid) {
			t.Fatalf("invalid Agile key width %d passed verification", bits)
		}
		if agileExtractKeyFromHash(h, invalid) != nil {
			t.Fatalf("invalid Agile key width %d extracted a key", bits)
		}
	}
}

func TestStandardDerivedKeyReusePreservesVerificationAndDecryption(t *testing.T) {
	password, info, key, encPkg := standardReuseFixture(t)
	if !standardVerifyKey(key, info) {
		t.Fatal("derived key rejected the valid Standard verifier")
	}
	want := []byte("standard payload")
	if got := standardDecryptKey(key, info, encPkg); !bytes.Equal(got, want) {
		t.Fatalf("reused key decrypted %q, want %q", got, want)
	}
	if got := standardDecrypt(password, info, encPkg); !bytes.Equal(got, want) {
		t.Fatalf("compatibility wrapper decrypted %q, want %q", got, want)
	}

	mutated := append([]byte(nil), key...)
	mutated[0] ^= 0xff
	if standardVerifyKey(mutated, info) {
		t.Fatal("mutated Standard key passed verification")
	}
	if got := standardDecryptKey(nil, info, encPkg); got != nil {
		t.Fatalf("invalid Standard key decrypted %q", got)
	}
}

func BenchmarkOfficePasswordDerivationReuse(b *testing.B) {
	password, agile, _ := agileReuseFixture(b)
	_, standard, _, standardPkg := standardReuseFixture(b)

	b.Run("agile/duplicate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !agileVerifyPW(password, agile) {
				b.Fatal("verification failed")
			}
			if key := agileExtractKey(password, agile); len(key) == 0 {
				b.Fatal("key extraction failed")
			}
		}
	})
	b.Run("agile/reuse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h := agilePasswordHash(password, agile)
			if !agileVerifyHash(h, agile) {
				b.Fatal("verification failed")
			}
			if key := agileExtractKeyFromHash(h, agile); len(key) == 0 {
				b.Fatal("key extraction failed")
			}
		}
	})
	b.Run("standard/duplicate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !standardVerifyPW(password, standard) {
				b.Fatal("verification failed")
			}
			if plain := standardDecrypt(password, standard, standardPkg); len(plain) == 0 {
				b.Fatal("decryption failed")
			}
		}
	})
	b.Run("standard/reuse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			key := standardMakeKey(password, standard)
			if !standardVerifyKey(key, standard) {
				b.Fatal("verification failed")
			}
			if plain := standardDecryptKey(key, standard, standardPkg); len(plain) == 0 {
				b.Fatal("decryption failed")
			}
		}
	})
}
