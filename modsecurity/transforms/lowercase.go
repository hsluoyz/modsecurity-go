package transforms

import (
	"strings"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

type TransLowerCase struct{}

func NewTransLowerCase() modsecurity.Trans {
	return &TransLowerCase{}
}

func (*TransLowerCase) Name() string {
	return "lowercase"
}
func (*TransLowerCase) Trans(s string) string {
	return strings.ToLower(s)
}
