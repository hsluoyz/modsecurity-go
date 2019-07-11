package transforms

import (
	"strings"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

type TransMapRune struct {
	name    string
	mapping func(rune) rune
}

func NewTransRemoveWhitespace() modsecurity.Trans {
	return &TransMapRune{
		name:    "removeWhitespace",
		mapping: replaceRune(' ', -1),
	}
}

func NewTransRemoveNulls() modsecurity.Trans {
	return &TransMapRune{
		name:    "removeNulls",
		mapping: replaceRune(0, -1),
	}
}

func NewTransReplaceNulls() modsecurity.Trans {
	return &TransMapRune{
		name:    "replaceNulls",
		mapping: replaceRune(0, ' '),
	}
}

func replaceRune(from, to rune) func(rune) rune {
	return func(i rune) rune {
		if i == from {
			return to
		}
		return i
	}
}

func (t *TransMapRune) Name() string {
	return t.name
}
func (t *TransMapRune) Trans(tr *modsecurity.Transaction, s string) string {
	return strings.Map(t.mapping, s)
}
