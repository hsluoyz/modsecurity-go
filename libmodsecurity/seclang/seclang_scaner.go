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
	LI(lex, StateInit, TkConfigContentInjection)
	LIQNumberArg(lex, StateInit, TkConfigDirAuditDirMod)
	LINumberArg(lex, StateInit, TkConfigDirAuditDirMod)
	LIQPathArg(lex, StateInit, TkConfigDirAuditDir)
	LIPathArg(lex, StateInit, TkConfigDirAuditDir)
	LIQFreeTextNewLineArg(lex, StateInit, TkConfigSecArgumentSeparator)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecArgumentSeparator)
	return lex
}
