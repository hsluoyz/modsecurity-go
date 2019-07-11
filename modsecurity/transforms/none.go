package transforms

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

type TransNone struct{}

func NewTransNone() modsecurity.Trans {
	return &TransNone{}
}

func (*TransNone) Name() string {
	return "none"
}
func (*TransNone) Trans(tr *modsecurity.Transaction, s string) string {
	return s
}
