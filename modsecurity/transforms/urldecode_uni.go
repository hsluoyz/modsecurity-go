package transforms

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/utils"
)

type TransUrlDecodeUni struct{}

func NewTransUrlDecodeUni() modsecurity.Trans {
	return &TransUrlDecodeUni{}
}

func (*TransUrlDecodeUni) Name() string {
	return "urlDecodeUni"
}
func (*TransUrlDecodeUni) Trans(s string) string {
	res, _ := utils.UrlDecodeUni(s)
	return res
}
