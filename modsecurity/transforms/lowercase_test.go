package transforms

import "testing"

func TestTransLowerCase(t *testing.T) {
	inputs := map[string]string{
		"abc": "abc",
		"Abc": "abc",
		"ABC": "abc",
	}
	tf := NewTransLowerCase()
	if tf.Name() != "lowercase" {
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
