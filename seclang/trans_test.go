package seclang

import (
	"strings"
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity/transforms"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

func TestMakeTrans(t *testing.T) {
	t.Run("lowercase", func(t *testing.T) {
		dr := newDireRule()
		input := `t:lowercase`
		scan := parser.NewSecLangScanner(strings.NewReader(input))
		parsed, err := scan.ReadActions()
		if err != nil {
			t.Error(err)
			return
		}
		err = dr.applyTrans(parsed.Trans)
		if err != nil {
			t.Error(err)
			return
		}
		trans := dr.rule.Trans
		if len(trans) != 1 {
			t.Error("expect one trans")
			return
		}
		if v, ok := trans[0].(*transforms.TransLowerCase); !ok {
			t.Errorf("except TransLowerCase got %#v", v)
			return
		}

	})
}
