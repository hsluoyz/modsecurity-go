package libmodsecruity

import "testing"

func TestSimpleDirectiveFromSecLang(t *testing.T) {
	var rule string
	rule = "SecRequestBodyAccess On"
	t.Run(rule, func(t *testing.T) {
		eng := NewEngine()
		rs, err := NewRuleSetFromSecLangString(rule)
		if err != nil {
			t.Error(err)
		}
		err = eng.AddRuleSet(rs)
		if err != nil {
			t.Error(err)
		}
		if eng.requestBodyAccess != true {
			t.Errorf("%s expect make requestBodyAccess ture but not", rule)
		}
	})
	rule = "SecResponseBodyAccess On"
	t.Run(rule, func(t *testing.T) {
		eng := NewEngine()
		rs, err := NewRuleSetFromSecLangString(rule)
		if err != nil {
			t.Error(err)
		}
		err = eng.AddRuleSet(rs)
		if err != nil {
			t.Error(err)
		}
		if eng.responseBodyAccess != true {
			t.Errorf("%s expect make responseBodyAccess ture but not", rule)
		}
	})
}
