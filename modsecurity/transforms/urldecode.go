package transforms

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/utils"
)

type TransUrlDecode struct{}

func NewTransUrlDecode() modsecurity.Trans {
	return &TransUrlDecode{}
}

func (*TransUrlDecode) Name() string {
	return "urlDecode"
}
func (*TransUrlDecode) Trans(tr *modsecurity.Transaction, s string) string {
	res, _ := utils.UrlDecode(s)
	return res
}
