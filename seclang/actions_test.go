package seclang

import (
	"strings"
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
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
		actions, err := MakeActions(parsed.Action)
		if err != nil {
			t.Error(err)
			return
		}
		if len(actions) != 1 {
			t.Error("expect one variable")
			return
		}
		if v, ok := actions[0].(*modsecurity.ActionDeny); !ok {
			t.Errorf("except ActionDeny got %#v", v)
			return
		}

	})
}
