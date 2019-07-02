package transforms

import "testing"

func TestTransLowerCase(t *testing.T) {
	inputs := map[string]string{
		"abc": "abc",
		"Abc": "abc",
		"ABC": "abc",
	}
	tf := NewTransLowerCase()
	for input, expect := range inputs {
		res := tf.Trans(input)
		if res != expect {
			t.Errorf("input %s got unexpected out %s", input, res)
		}
	}
}
