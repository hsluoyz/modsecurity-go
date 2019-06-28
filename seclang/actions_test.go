package seclang

import (
	"strings"
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity/actions"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

func TestMakeActions(t *testing.T) {
	t.Run("deny", func(t *testing.T) {
		input := `deny`
		scan := parser.NewSecLangScanner(strings.NewReader(input))
		parsed, err := scan.ReadActions()
		if err != nil {
			t.Error(err)
			return
		}
		a, err := MakeActions(parsed.Action)
		if err != nil {
			t.Error(err)
			return
		}
		if len(a) != 1 {
			t.Error("expect one variable")
			return
		}
		if v, ok := a[0].(*actions.ActionDeny); !ok {
			t.Errorf("except ActionDeny got %#v", v)
			return
		}

	})
}
