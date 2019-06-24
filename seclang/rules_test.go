package seclang

import (
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func TestRules(t *testing.T) {
	var rule string
	rule = "SecRequestBodyAccess On"
	t.Run(rule, func(t *testing.T) {
		eng := modsecurity.NewEngine()
		rs, err := NewDireSetFromSecLangString(rule)
		if err != nil {
			t.Error(err)
			return
		}
		err = rs.Execute(eng)
		if err != nil {
			t.Error(err)
			return
		}
		if eng.RequestBodyAccess != true {
			t.Errorf("%s expect make requestBodyAccess ture but not", rule)
			return
		}
	})
	rule = "SecResponseBodyAccess On"
	t.Run(rule, func(t *testing.T) {
		eng := modsecurity.NewEngine()
		rs, err := NewDireSetFromSecLangString(rule)
		if err != nil {
			t.Error(err)
			return
		}
		err = rs.Execute(eng)
		if err != nil {
			t.Error(err)
			return
		}
		if eng.ResponseBodyAccess != true {
			t.Errorf("%s expect make responseBodyAccess ture but not", rule)
			return
		}
	})
	rule = "SecRuleEngine On"
	t.Run(rule, func(t *testing.T) {
		eng := modsecurity.NewEngine()
		rs, err := NewDireSetFromSecLangString(rule)
		if err != nil {
			t.Error(err)
			return
		}
		err = rs.Execute(eng)
		if err != nil {
			t.Error(err)
			return
		}
		if eng.Enabled != true {
			t.Errorf("%s expect make Enabled ture but not", rule)
			return
		}
		if eng.DetectionOnly == true {
			t.Errorf("%s expect make DetectionOnly false but not", rule)
			return
		}
	})
}
