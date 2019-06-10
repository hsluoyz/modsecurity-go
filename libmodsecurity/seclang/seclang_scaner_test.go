package seclang

import (
	"testing"
)

type expect struct {
	tk  int
	str []string
}

func TestSecLangLexComnands(t *testing.T) {
	DEBUG = true
	defer func() { DEBUG = false }()
	lex := NewSecLangLex()
	datas := map[string]expect{
		`SecComponentSignature "core ruleset/2.1.3"`:         {TkConfigComponentSig, []string{`core ruleset/2.1.3`}},
		`SecServerSignature "Microsoft-IIS/6.0"`:             {TkConfigSecServerSig, []string{`Microsoft-IIS/6.0`}},
		`SecWebAppId "WebApp1"`:                              {TkConfigSecWebAppId, []string{`WebApp1`}},
		`SecWebAppId "WebApp1\nnewline"`:                     {TkConfigSecWebAppId, []string{`WebApp1\nnewline`}},
		`SecContentInjection On`:                             {TkConfigContentInjection, []string{}},
		`SecAuditLogDirMode 02750`:                           {TkConfigDirAuditDirMod, []string{`02750`}},
		`SecAuditLogDirMode "02750"`:                         {TkConfigDirAuditDirMod, []string{`02750`}},
		`SecAuditLogStorageDir /usr/local/apache/logs/audit`: {TkConfigDirAuditDir, []string{`/usr/local/apache/logs/audit`}},
		`SecAuditLogStorageDir "logs/audit"`:                 {TkConfigDirAuditDir, []string{`logs/audit`}},
		`SecArgumentSeparator &`:                             {TkConfigSecArgumentSeparator, []string{`&`}},
		`SecArgumentSeparator "#"`:                           {TkConfigSecArgumentSeparator, []string{`#`}},
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
		if len(exp.str) != len(token.Value) {
			t.Errorf("expected %s[%d] val: %q, got %q", TkRegex(exp.tk), exp.tk, exp.str, token.Value)
			return
		}
		for idx, str := range exp.str {
			if token.Value[idx].(string) != str {
				t.Errorf("expected %s[%d] val: %s, got %s", TkRegex(exp.tk), exp.tk, exp.str, token.String())
				return
			}
		}
	}
}
