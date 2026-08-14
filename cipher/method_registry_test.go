package cipher

import "testing"

func TestParseViewTurboPasswordHashMarker(t *testing.T) {
	token, enabled := parseViewTurboPassword("example-token#VT")
	if !enabled || token != "example-token" {
		t.Fatalf("parseViewTurboPassword returned token=%q enabled=%v", token, enabled)
	}
}

func TestParseViewTurboPasswordLegacySuffix(t *testing.T) {
	password := "12345678901234567890123456789012VT"
	token, enabled := parseViewTurboPassword(password)
	if !enabled || token != password[:32] {
		t.Fatalf("legacy marker returned token=%q enabled=%v", token, enabled)
	}
}

func TestParseViewTurboPasswordLeavesNormalPasswordUntouched(t *testing.T) {
	password := "ordinary-password"
	token, enabled := parseViewTurboPassword(password)
	if enabled || token != password {
		t.Fatalf("normal password returned token=%q enabled=%v", token, enabled)
	}
}
