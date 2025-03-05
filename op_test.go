package locket

import "testing"

func TestOp(t *testing.T) {
	var o = item{
		vault:   "my-vault",
		item:    "my-item",
		section: "my-section",
		field:   "my-field",
		otp:     true,
	}
	t.Logf("op: %s", o.string())
}
