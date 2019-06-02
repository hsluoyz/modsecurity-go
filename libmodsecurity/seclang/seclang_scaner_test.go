package seclang

import (
	"testing"
)

type expect struct {
	tk  int
	str string
}

func TestSecLangLexComnands(t *testing.T) {
	DEBUG = true
	defer func() { DEBUG = false }()
	lex := NewSecLangLex()
	datas := map[string]expect{
		`SecComponentSignature "core ruleset/2.1.3"`: {TkConfigComponentSig, `core ruleset/2.1.3`},
		`SecServerSignature "Microsoft-IIS/6.0"`:     {TkConfigSecServerSig, `Microsoft-IIS/6.0`},
		`SecWebAppId "WebApp1"`:                      {TkConfigSecWebAppId, `WebApp1`},
		`SecWebAppId "WebApp1\nnewline"`:             {TkConfigSecWebAppId, `WebApp1\nnewline`},
	}
	for rule, exp := range datas {
		scan, err := lex.Scanner([]byte(rule))
		if err != nil {
			t.Error(err)
			return
		}
		tok, err, eos := scan.Next()
		if err != nil {
			t.Error(err)
			return
		}
		if eos {
			t.Errorf("unexpected eos, %s, %#v", rule, exp)
			return
		}
		token := tok.(*Token)
		if token.Type != exp.tk {
			t.Errorf("expected %s[%d], got %s", TkRegex(exp.tk), exp.tk, token.String())
			return
		}
		if string(token.Value.([]byte)) != exp.str {
			t.Errorf("expected %s[%d] val: %s, got %s", TkRegex(exp.tk), exp.tk, exp.str, token.String())
			return
		}
	}
}
