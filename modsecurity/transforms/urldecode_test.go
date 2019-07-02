package transforms

import "testing"

func TestTransUrlDecode(t *testing.T) {
	inputs := map[string]string{
		"abcde+123456%e4%bd%a0%e5%a5%bd%u4F60%u597D": "abcde 123456你好%u4F60%u597D",
	}
	tf := NewTransUrlDecode()
	for input, expect := range inputs {
		res := tf.Trans(input)
		if res != expect {
			t.Errorf("input %s got unexpected out %s", input, res)
		}
	}
}
