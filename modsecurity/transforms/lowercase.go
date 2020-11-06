package transforms

import (
	"strings"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

type TransLowerCase struct{}

func NewTransLowerCase() modsecurity.Trans {
	return &TransLowerCase{}
}

func (*TransLowerCase) Name() string {
	return "lowercase"
}
func (*TransLowerCase) Trans(tr *modsecurity.Transaction, s string) string {
	return strings.ToLower(s)
}
