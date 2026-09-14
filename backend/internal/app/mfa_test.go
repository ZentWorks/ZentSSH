package app

import (
	"testing"
	"time"
)

func TestTOTPAtRFC6238VectorTruncatedToSixDigits(t *testing.T) {
	// RFC 6238 SHA-1 test secret: ASCII "12345678901234567890".
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	got, err := totpAt(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("code = %s, want 287082", got)
	}
	if !verifyTOTP(secret, got, time.Unix(59, 0)) {
		t.Fatal("valid TOTP rejected")
	}
	if verifyTOTP(secret, "000000", time.Unix(59, 0)) {
		t.Fatal("invalid TOTP accepted")
	}
}

func TestRecoveryHashNormalizesFormatting(t *testing.T) {
	if recoveryHash("ABCD-EFGH-JKLM") != recoveryHash("abcd efgh jklm") {
		t.Fatal("recovery code normalization mismatch")
	}
}
