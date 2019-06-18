package seclang

import (
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func TestSimpleDirectiveFromSecLang(t *testing.T) {
	var rule string
	rule = "SecRequestBodyAccess On"
	t.Run(rule, func(t *testing.T) {
		eng := modsecurity.NewEngine()
		rs, err := NewRuleSetFromSecLangString(rule)
		if err != nil {
			t.Error(err)
		}
		err = rs.Execute(eng)
		if err != nil {
			t.Error(err)
		}
		if eng.RequestBodyAccess != true {
			t.Errorf("%s expect make requestBodyAccess ture but not", rule)
		}
	})
	rule = "SecResponseBodyAccess On"
	t.Run(rule, func(t *testing.T) {
		eng := modsecurity.NewEngine()
		rs, err := NewRuleSetFromSecLangString(rule)
		if err != nil {
			t.Error(err)
		}
		err = rs.Execute(eng)
		if err != nil {
			t.Error(err)
		}
		if eng.ResponseBodyAccess != true {
			t.Errorf("%s expect make responseBodyAccess ture but not", rule)
		}
	})
}
