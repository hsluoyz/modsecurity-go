package seclang

import (
	"fmt"
	"testing"

	"github.com/timtadh/lexmachine/machines"
)

func TestSimpleSecRule(t *testing.T) {
	const (
		TkSecRule = 1 + iota
		TkFullRequest
	)
	const (
		StateSecRule = 1 + iota
	)
	lex := NewLexer()
	lex.AddString(StateInit, "SecRule", func(scan *Scanner, match *machines.Match) (interface{}, error) {
		scan.SetState(StateSecRule)
		return scan.Token(TkSecRule, "SecRule", match), nil
	})
	lex.Add(StateInit, []byte("( |\t|\n|\r)+"), func(scan *Scanner, match *machines.Match) (interface{}, error) {
		return nil, nil
	})
	lex.AddString(StateSecRule, "FULL_REQUEST", func(scan *Scanner, match *machines.Match) (interface{}, error) {
		return scan.Token(TkFullRequest, "FULL_REQUEST", match), nil
	})
	lex.Add(StateSecRule, []byte("( |\t|\n|\r)+"), func(scan *Scanner, match *machines.Match) (interface{}, error) {
		return nil, nil
	})
	expected := []string{
		"SecRule",
		"FULL_REQUEST",
	}
	scan, err := lex.Scanner([]byte("SecRule FULL_REQUEST"))
	if err != nil {
		t.Error(err)
	}
	for _, e := range expected {
		tok, err, eos := scan.Next()
		if err != nil {
			t.Errorf("unexpected error:%s", err.Error())
		}
		token := tok.(*Token)
		if eos {
			t.Errorf("unexpected eos, token :%s", token.String())
		}
		if token.Value.(string) != e {
			t.Errorf("Want %s, get :%s", e, token.Value)
		}
		fmt.Println(token.String())
	}
}

func TestCaseInsensitive(t *testing.T) {
	excepted := map[string]string{
		"ab":    "[aA][bB]",
		"Ab":    "[aA][bB]",
		"AB":    "[aA][bB]",
		"你好":    "你好",
		"ab|cd": "[aA][bB]|[cC][dD]",
	}
	for in, out := range excepted {
		if res := toCaseInsensitiveRegex(in); res != out {
			t.Errorf("excepted: %s got %s", out, res)
		}
	}
}
