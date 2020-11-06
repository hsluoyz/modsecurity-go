package seclang

import (
	"strings"
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity/actions"
	"github.com/hsluoyz/modsecurity-go/seclang/parser"
)

func TestApplyActions(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		input := `id:123,phase:2,deny`
		scan := parser.NewSecLangScanner(strings.NewReader(input))
		parsed, err := scan.ReadActions()
		if err != nil {
			t.Error(err)
			return
		}
		dr := newDireRule()
		err = dr.applyActions(parsed)
		if err != nil {
			t.Error(err)
			return
		}
		a := dr.rule.Actions
		if len(a) != 1 {
			t.Error("expect one variable")
			return
		}
		if dr.rule.Id != 123 {
			t.Errorf("unexpected id %d", dr.rule.Id)
		}
		if dr.rule.Phase != 2 {
			t.Errorf("unexpected phase %d", dr.rule.Phase)
		}
		if v, ok := a[0].(*actions.ActionDeny); !ok {
			t.Errorf("except ActionDeny got %#v", v)
			return
		}

	})
	t.Run("basic", func(t *testing.T) {
		input := `id:333,phase:1,tag:'tag123',msg:'msg321',rev:'1.1',ver:'my-rule/123'`
		scan := parser.NewSecLangScanner(strings.NewReader(input))
		parsed, err := scan.ReadActions()
		if err != nil {
			t.Error(err)
			return
		}
		dr := newDireRule()
		err = dr.applyActions(parsed)
		if err != nil {
			t.Error(err)
			return
		}
		a := dr.rule.Actions
		if len(a) != 0 {
			t.Error("expect no variable")
			return
		}
		if dr.rule.Id != 333 {
			t.Errorf("unexpected id %d", dr.rule.Id)
		}
		if dr.rule.Phase != 1 {
			t.Errorf("unexpected phase %d", dr.rule.Phase)
		}
		if dr.rule.MetaData["tag"][0] != "tag123" {
			t.Errorf("unexpected tag %q", dr.rule.MetaData["tag"])
		}
		if dr.rule.MetaData["msg"][0] != "msg321" {
			t.Errorf("unexpected msg %q", dr.rule.MetaData["msg"])
		}
		if dr.rule.MetaData["rev"][0] != "1.1" {
			t.Errorf("unexpected rev %q", dr.rule.MetaData["rev"])
		}
		if dr.rule.MetaData["ver"][0] != "my-rule/123" {
			t.Errorf("unexpected ver %q", dr.rule.MetaData["ver"])
		}
	})
}
