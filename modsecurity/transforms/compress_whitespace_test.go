package transforms

import "testing"

func TestTransCompressWhitespace(t *testing.T) {
	inputs := map[string]string{
		" a  b   c ":  " a b c ",
		"   abc   ":   " abc ",
		"   a b c   ": " a b c ",
	}
	tf := NewTransCompressWhitespace()
	if tf.Name() != "compressWhitespace" {
		t.Errorf("unexpect transform name %s", tf.Name())
		return
	}
	for input, expect := range inputs {
		res := tf.Trans(input)
		if res != expect {
			t.Errorf("input %s got unexpected out %s", input, res)
		}
	}
}
