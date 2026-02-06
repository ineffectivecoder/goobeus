package crypto

import (
	"encoding/hex"
	"testing"
)

func TestHMACSHA1AES256(t *testing.T) {
	// Reference values from Impacket with key usage 17 and 0x99 derivation:
	// Key: 6c69306119a5085703cc4f4bf55623da8966c0538303ccb01657d163889b86ae
	// Data: "test data"
	// Expected checksum: 5a28979c5c13bdf860941c42

	key, _ := hex.DecodeString("6c69306119a5085703cc4f4bf55623da8966c0538303ccb01657d163889b86ae")
	data := []byte("test data")
	expected := "5a28979c5c13bdf860941c42"

	result, err := HMACSHA1AES256(key, data)
	if err != nil {
		t.Fatalf("HMACSHA1AES256 failed: %v", err)
	}

	resultHex := hex.EncodeToString(result)
	t.Logf("Our result:  %s", resultHex)
	t.Logf("Expected:    %s", expected)

	if resultHex != expected {
		t.Errorf("Checksum mismatch: got %s, want %s", resultHex, expected)
	}
}
