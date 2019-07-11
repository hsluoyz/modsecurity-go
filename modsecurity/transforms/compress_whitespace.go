package transforms

import (
	"strings"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

type TransCompressWhitespace struct {
}

func NewTransCompressWhitespace() modsecurity.Trans {
	return &TransCompressWhitespace{}
}

func (t *TransCompressWhitespace) Name() string {
	return "compressWhitespace"
}
func (t *TransCompressWhitespace) Trans(tr *modsecurity.Transaction, s string) string {
	var previousIsSpace bool
	return strings.Map(func(i rune) rune {
		if i == ' ' {
			if previousIsSpace {
				return -1
			}
			previousIsSpace = true
		} else {
			previousIsSpace = false
		}
		return i
	}, s)
}
