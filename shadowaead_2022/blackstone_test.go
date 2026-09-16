package shadowaead_2022

import (
	"encoding/base64"
	"testing"

	C "github.com/metacubex/sing-shadowsocks2/cipher"
)

func TestBlackstoneExactSuffixPreservesKeyDecoding(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	for _, test := range []struct {
		password string
		enabled  bool
	}{
		{password: key, enabled: false},
		{password: key + "#BLACKSTONE", enabled: true},
		{password: key + "#blackstone", enabled: true},
	} {
		created, err := NewMethod(
			"2022-blake3-aes-128-gcm",
			C.MethodOptions{Password: test.password},
		)
		if err != nil {
			t.Fatalf("NewMethod(%q): %v", test.password, err)
		}
		method := created.(*Method)
		if method.blackstone != test.enabled {
			t.Fatalf("NewMethod(%q) blackstone=%v", test.password, method.blackstone)
		}
		if len(method.pskList) != 1 || len(method.pskList[0]) != 16 {
			t.Fatalf("NewMethod(%q) changed key decoding", test.password)
		}
	}
}
