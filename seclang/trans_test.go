package seclang

import (
	"strings"
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

func TestMakeTrans(t *testing.T) {
	t.Run("lowercase", func(t *testing.T) {
		input := `t:lowercase`
		scan := parser.NewSecLangScanner(strings.NewReader(input))
		parsed, err := scan.ReadActions()
		if err != nil {
			t.Error(err)
			return
		}
		trans, err := MakeTrans(parsed.Trans)
		if err != nil {
			t.Error(err)
			return
		}
		if len(trans) != 1 {
			t.Error("expect one trans")
			return
		}
		if v, ok := trans[0].(*modsecurity.TransLowerCase); !ok {
			t.Errorf("except TransLowerCase got %#v", v)
			return
		}

	})
}
