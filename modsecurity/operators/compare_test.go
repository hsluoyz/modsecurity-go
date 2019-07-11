package operators

import (
	"testing"
)

func TestOperatorEq(t *testing.T) {
	t.Run("expect error", func(t *testing.T) {
		_, err := NewOperatorEq("xx")
		if err == nil {
			t.Error("expect error")
		}
		_, err = NewOperatorEq("")
		if err == nil {
			t.Error("expect error")
		}
	})
	t.Run("match with 5", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": false,
			"-5":  false,
			"-1":  false,
			"0":   false,
			"1":   false,
			"3":   false,
			"5":   true,
			"8":   false,
			"20":  false,
			"":    false,
			"xxx": false,
		}
		op, err := NewOperatorEq("5")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "eq" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "5" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
	t.Run("match with 0", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": false,
			"-5":  false,
			"-1":  false,
			"0":   true,
			"1":   false,
			"3":   false,
			"5":   false,
			"8":   false,
			"20":  false,
			"":    true,
			"xxx": true,
		}
		op, err := NewOperatorEq("0")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "eq" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "0" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
	t.Run("match with -5", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": false,
			"-5":  true,
			"-1":  false,
			"0":   false,
			"1":   false,
			"3":   false,
			"5":   false,
			"8":   false,
			"20":  false,
			"":    false,
			"xxx": false,
		}
		op, err := NewOperatorEq("-5")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "eq" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "-5" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
}

func TestOperatorGe(t *testing.T) {
	t.Run("expect error", func(t *testing.T) {
		_, err := NewOperatorGe("xx")
		if err == nil {
			t.Error("expect error")
		}
		_, err = NewOperatorGe("")
		if err == nil {
			t.Error("expect error")
		}
	})
	t.Run("match with 5", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": false,
			"-5":  false,
			"-1":  false,
			"0":   false,
			"1":   false,
			"3":   false,
			"5":   true,
			"8":   true,
			"20":  true,
			"":    false,
			"xxx": false,
		}
		op, err := NewOperatorGe("5")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "ge" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "5" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
	t.Run("match with 0", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": false,
			"-5":  false,
			"-1":  false,
			"0":   true,
			"1":   true,
			"3":   true,
			"5":   true,
			"8":   true,
			"20":  true,
			"":    true,
			"xxx": true,
		}
		op, err := NewOperatorGe("0")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "ge" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "0" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
	t.Run("match with -5", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": false,
			"-5":  true,
			"-1":  true,
			"0":   true,
			"1":   true,
			"3":   true,
			"5":   true,
			"8":   true,
			"20":  true,
			"":    true,
			"xxx": true,
		}
		op, err := NewOperatorGe("-5")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "ge" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "-5" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
}

func TestOperatorGt(t *testing.T) {
	t.Run("expect error", func(t *testing.T) {
		_, err := NewOperatorGt("xx")
		if err == nil {
			t.Error("expect error")
		}
		_, err = NewOperatorGt("")
		if err == nil {
			t.Error("expect error")
		}
	})
	t.Run("match with 5", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": false,
			"-5":  false,
			"-1":  false,
			"0":   false,
			"1":   false,
			"3":   false,
			"5":   false,
			"8":   true,
			"20":  true,
			"":    false,
			"xxx": false,
		}
		op, err := NewOperatorGt("5")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "gt" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "5" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
	t.Run("match with 0", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": false,
			"-5":  false,
			"-1":  false,
			"0":   false,
			"1":   true,
			"3":   true,
			"5":   true,
			"8":   true,
			"20":  true,
			"":    false,
			"xxx": false,
		}
		op, err := NewOperatorGt("0")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "gt" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "0" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
	t.Run("match with -5", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": false,
			"-5":  false,
			"-1":  true,
			"0":   true,
			"1":   true,
			"3":   true,
			"5":   true,
			"8":   true,
			"20":  true,
			"":    true,
			"xxx": true,
		}
		op, err := NewOperatorGt("-5")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "gt" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "-5" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
}

func TestOperatorLt(t *testing.T) {
	t.Run("expect error", func(t *testing.T) {
		_, err := NewOperatorLt("xx")
		if err == nil {
			t.Error("expect error")
		}
		_, err = NewOperatorLt("")
		if err == nil {
			t.Error("expect error")
		}
	})
	t.Run("match with 5", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": true,
			"-5":  true,
			"-1":  true,
			"0":   true,
			"1":   true,
			"3":   true,
			"5":   false,
			"8":   false,
			"20":  false,
			"":    true,
			"xxx": true,
		}
		op, err := NewOperatorLt("5")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "lt" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "5" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
	t.Run("match with 0", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": true,
			"-5":  true,
			"-1":  true,
			"0":   false,
			"1":   false,
			"3":   false,
			"5":   false,
			"8":   false,
			"20":  false,
			"":    false,
			"xxx": false,
		}
		op, err := NewOperatorLt("0")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "lt" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "0" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
	t.Run("match with -5", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": true,
			"-5":  false,
			"-1":  false,
			"0":   false,
			"1":   false,
			"3":   false,
			"5":   false,
			"8":   false,
			"20":  false,
			"":    false,
			"xxx": false,
		}
		op, err := NewOperatorLt("-5")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "lt" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "-5" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
}

func TestOperatorLe(t *testing.T) {
	t.Run("expect error", func(t *testing.T) {
		_, err := NewOperatorLe("xx")
		if err == nil {
			t.Error("expect error")
		}
		_, err = NewOperatorLe("")
		if err == nil {
			t.Error("expect error")
		}
	})
	t.Run("match with 5", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": true,
			"-5":  true,
			"-1":  true,
			"0":   true,
			"1":   true,
			"3":   true,
			"5":   true,
			"8":   false,
			"20":  false,
			"":    true,
			"xxx": true,
		}
		op, err := NewOperatorLe("5")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "le" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "5" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
	t.Run("match with 0", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": true,
			"-5":  true,
			"-1":  true,
			"0":   true,
			"1":   false,
			"3":   false,
			"5":   false,
			"8":   false,
			"20":  false,
			"":    true,
			"xxx": true,
		}
		op, err := NewOperatorLe("0")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "le" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "0" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
	t.Run("match with -5", func(t *testing.T) {
		inputs := map[string]bool{
			"-10": true,
			"-5":  true,
			"-1":  false,
			"0":   false,
			"1":   false,
			"3":   false,
			"5":   false,
			"8":   false,
			"20":  false,
			"":    false,
			"xxx": false,
		}
		op, err := NewOperatorLe("-5")
		if err != nil {
			t.Error(err)
			return
		}
		if op.Name() != "le" {
			t.Errorf("unexpected name %s", op.Name())
			return
		}
		if op.Args() != "-5" {
			t.Errorf("unexpected args %s", op.Args())
			return
		}
		for input, expect := range inputs {
			res := op.Match(nil, input)
			if res != expect {
				t.Errorf("input '%s' got unexpected res %t", input, res)
			}
		}
	})
}
