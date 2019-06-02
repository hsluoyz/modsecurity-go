package seclang

import "github.com/timtadh/lexmachine/machines"

// NewSecLangLex generate new SecLang Lexer
func NewSecLangLex() *Lexer {
	lex := NewLexer()
	// skip space
	lex.Add(StateInit, []byte("( |\t|\n|\r)+"), func(scan *Scanner, match *machines.Match) (interface{}, error) {
		return nil, nil
	})
	LIQFreeTextArg(lex, StateInit, TkConfigComponentSig)
	LIQFreeTextArg(lex, StateInit, TkConfigSecServerSig)
	LIQFreeTextArg(lex, StateInit, TkConfigSecWebAppId)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecWebAppId)
	return lex
}
