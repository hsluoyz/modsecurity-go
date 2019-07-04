package operators

import "testing"

func TestOperatorRx(t *testing.T) {
	t.Run("expect error", func(t *testing.T) {
		_, err := NewOperatorRx("[")
		if err == nil {
			t.Error("expect error")
		}
		_, err = NewOperatorRx("(")
		if err == nil {
			t.Error("expect error")
		}
	})
	t.Run("match with ab?c[0-9]", func(t *testing.T) {
		inputs := map[string]bool{
			"ac0":  true,
			"abc1": true,
			"bc1":  false,
			"xxx":  false,
			"":     false,
		}
		op, err := NewOperatorRx("ab?c[0-9]")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "rx" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "ab?c[0-9]" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
}
