package transforms

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/utils"
)

type TransUrlDecodeUni struct{}

func NewTransUrlDecodeUni() modsecurity.Trans {
	return &TransUrlDecodeUni{}
}

func (*TransUrlDecodeUni) Name() string {
	return "urlDecodeUni"
}
func (*TransUrlDecodeUni) Trans(tr *modsecurity.Transaction, s string) string {
	res, _ := utils.UrlDecodeUni(s)
	return res
}
