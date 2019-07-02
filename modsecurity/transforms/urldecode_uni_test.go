package transforms

import "testing"

func TestTransUrlDecodeUni(t *testing.T) {
	inputs := map[string]string{
		"abcde+123456%e4%bd%a0%e5%a5%bd%u4F60%u597D": "abcde 123456你好你好",
	}
	tf := NewTransUrlDecodeUni()
	for input, expect := range inputs {
		res := tf.Trans(input)
		if res != expect {
			t.Errorf("input %s got unexpected out %s", input, res)
		}
	}
}
