package transforms

import "testing"

func TestTransRemoveWhitespace(t *testing.T) {
	inputs := map[string]string{
		" a b c de f":       "abcdef",
		" a    b c de f   ": "abcdef",
	}
	tf := NewTransRemoveWhitespace()
	if tf.Name() != "removeWhitespace" {
		t.Errorf("unexpect transform name %s", tf.Name())
		return
	}
	for input, expect := range inputs {
		res := tf.Trans(nil, input)
		if res != expect {
			t.Errorf("input %s got unexpected out %s", input, res)
		}
	}
}

func TestTransRemoveNulls(t *testing.T) {
	input := []byte(" a bcd  ef  ")
	input[0] = 0
	input[2] = 0
	input[6] = 0
	input[7] = 0
	input[10] = 0
	input[11] = 0
	inputs := map[string]string{
		string(input): "abcdef",
	}
	tf := NewTransRemoveNulls()
	if tf.Name() != "removeNulls" {
		t.Errorf("unexpect transform name %s", tf.Name())
		return
	}
	for input, expect := range inputs {
		res := tf.Trans(nil, input)
		if res != expect {
			t.Errorf("input %s got unexpected out %s", input, res)
		}
	}
}

func TestTransReplaceNulls(t *testing.T) {
	input := []byte(" a bcd  ef  ")
	input[0] = 0
	input[2] = 0
	input[6] = 0
	input[7] = 0
	input[10] = 0
	input[11] = 0
	inputs := map[string]string{
		string(input): " a bcd  ef  ",
	}
	tf := NewTransReplaceNulls()
	if tf.Name() != "replaceNulls" {
		t.Errorf("unexpect transform name %s", tf.Name())
		return
	}
	for input, expect := range inputs {
		res := tf.Trans(nil, input)
		if res != expect {
			t.Errorf("input %s got unexpected out %s", input, res)
		}
	}
}
