package transforms

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/utils"
)

type TransUrlDecode struct{}

func NewTransUrlDecode() modsecurity.Trans {
	return &TransUrlDecode{}
}

func (*TransUrlDecode) Name() string {
	return "urlDecode"
}
func (*TransUrlDecode) Trans(s string) string {
	res, _ := utils.UrlDecode(s)
	return res
}
