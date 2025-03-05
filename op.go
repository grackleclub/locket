package locket

import "fmt"

var (
	envTokenName = "OP_SERVICE_ACCOUNT_TOKEN"
	vaults       []vault
)

type vault struct {
	ID    string
	Title string
}

type item struct {
	vault   string
	item    string
	section string
	field   string
	otp     bool
}

func (o *item) string() string {
	var s string
	if o.section != "" {
		s = fmt.Sprintf("op://%s/%s/%s/%s",
			o.vault,
			o.item,
			o.section,
			o.field)
	} else {
		s = fmt.Sprintf("op://%s/%s/%s",
			o.vault,
			o.item,
			o.field,
		)
	}
	if o.otp {
		s += "?attribute=otp"
	}
	return s
}
