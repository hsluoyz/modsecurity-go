package transforms

import "testing"

func TestTransNone(t *testing.T) {
	inputs := []string{
		"abc",
		"Abc",
		"ABC",
	}
	tf := NewTransNone()
	if tf.Name() != "none" {
		t.Errorf("unexpect transform name %s", tf.Name())
		return
	}
	for _, expect := range inputs {
		res := tf.Trans(nil, expect)
		if res != expect {
			t.Errorf("input %s got unexpected out %s", expect, res)
		}
	}
}
