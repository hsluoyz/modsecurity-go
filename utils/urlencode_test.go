package utils

import "testing"

func TestUrlDecode(t *testing.T) {
	inputs := map[string]struct {
		res      string
		errCount int
	}{
		"abcde123456":                   {"abcde123456", 0},
		"abcde+123456":                  {"abcde 123456", 0},
		"abcde%20123456":                {"abcde 123456", 0},
		"%3c123%3e*aab":                 {"<123>*aab", 0},
		"!%40%23%24%25%5e%26*()_%2b%7c": {"!@#$%^&*()_+|", 0},
		"%e4%bd%a0%e5%a5%bd":            {"你好", 0},
		"%%3e*aab":                      {"%>*aab", 1},
		"%u4F60%u597D":                  {"%u4F60%u597D", 2},
		"%uFF10%uFF11":                  {"%uFF10%uFF11", 2},
	}

	for input, expect := range inputs {
		res, errCount := UrlDecode(input)
		if res != expect.res || errCount != expect.errCount {
			t.Errorf("input %s, got unexpected result %s, %d", input, res, errCount)
		}
	}
}

func TestUrlDecodeUni(t *testing.T) {
	inputs := map[string]struct {
		res      string
		errCount int
	}{
		"abcde123456":                   {"abcde123456", 0},
		"abcde+123456":                  {"abcde 123456", 0},
		"abcde%20123456":                {"abcde 123456", 0},
		"%3c123%3e*aab":                 {"<123>*aab", 0},
		"!%40%23%24%25%5e%26*()_%2b%7c": {"!@#$%^&*()_+|", 0},
		"%e4%bd%a0%e5%a5%bd":            {"你好", 0},
		"%%3e*aab":                      {"%>*aab", 1},
		"%u4F60%u597D":                  {"你好", 0},
		"%uFF10%uFF11":                  {"01", 0},
	}

	for input, expect := range inputs {
		res, errCount := UrlDecodeUni(input)
		if res != expect.res || errCount != expect.errCount {
			t.Errorf("input %s, got unexpected result %s, %d", input, res, errCount)
		}
	}
}
