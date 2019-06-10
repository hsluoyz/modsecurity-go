package seclang

import (
	"bytes"
	"errors"
	"fmt"

	dfapkg "github.com/timtadh/lexmachine/dfa"
	"github.com/timtadh/lexmachine/frontend"
	"github.com/timtadh/lexmachine/machines"
)

var DEBUG = false

const (
	StateInit = iota
)

type Action func(scan *Scanner, match *machines.Match) (interface{}, error)

type pattern struct {
	regex  []byte
	action Action
}

type Lexer struct {
	states map[int][]*pattern
	dfas   map[int]*dfapkg.DFA
}
type Scanner struct {
	lexer   *Lexer
	Text    []byte
	TC      int
	pTC     int
	sLine   int
	sColumn int
	eLine   int
	eColumn int
	states  *StateStack
}

func NewLexer() *Lexer {
	return &Lexer{
		states: make(map[int][]*pattern),
		dfas:   make(map[int]*dfapkg.DFA),
	}
}

func (l *Lexer) Add(state int, regex []byte, action Action) {
	l.states[state] = append(l.states[state], &pattern{regex, action})
}

func (l *Lexer) AddString(state int, s string, action Action) {
	l.Add(state, []byte(s), action)
}

func (l *Lexer) AddStringI(state int, s string, action Action) {
	l.AddString(state, toCaseInsensitiveRegex(s), action)
}

func (l *Lexer) Compile() error {
	for idx, pattern := range l.states {
		if DEBUG {
			fmt.Printf("state: %d\n", idx)
			for _, p := range pattern {
				fmt.Printf("pattern: %s\n", string(p.regex))
			}
		}
		dfa, err := compile(pattern)
		if err != nil {
			return err
		}
		l.dfas[idx] = dfa
	}
	return nil
}
func (l *Lexer) Scanner(text []byte) (*Scanner, error) {
	if len(l.dfas) == 0 && l.dfas[StateInit] == nil {
		err := l.Compile()
		if err != nil {
			return nil, err
		}
		if l.dfas[StateInit] == nil {
			return nil, errors.New("no entry in init state")
		}
	}

	// prevent the user from modifying the text under scan
	// textCopy := make([]byte, len(text))
	return &Scanner{
		lexer:  l,
		Text:   text,
		TC:     0,
		states: NewStateStack(),
	}, nil
}

func (s *Scanner) Next() (tok interface{}, err error, eos bool) {
	var token interface{}
	text := s.Text
	dfa, has := s.lexer.dfas[s.State()]
	if !has || dfa == nil {
		return nil, fmt.Errorf("state[dfa]: %d not found", s.State()), false
	}

	patterns, has := s.lexer.states[s.State()]
	if !has || patterns == nil {
		return nil, fmt.Errorf("state[state] %d not found", s.State()), false
	}

	scan := machines.DFALexerEngine(
		dfa.Start,
		dfa.Error, dfa.Trans,
		dfa.Accepting,
		text,
	)
	for token == nil {
		tc, match, err, scan := scan(s.TC)
		if scan == nil {
			return nil, nil, true
		} else if err != nil {
			return nil, err, false
		} else if match == nil {
			return nil, fmt.Errorf("No match but no error"), false
		}
		s.pTC = s.TC
		s.TC = tc
		s.sLine = match.StartLine
		s.sColumn = match.StartColumn
		s.eLine = match.EndLine
		s.eColumn = match.EndColumn

		pattern := patterns[match.PC]
		token, err = pattern.action(s, match)
		if err != nil {
			return nil, err, false
		}
	}
	return token, nil, false
}

func (s *Scanner) ToState(n ...int) {
	for i := len(n) - 1; i >= 0; i-- {
		s.states.Push(n[i])
	}
}

func (s *Scanner) State() int {
	return s.states.Top()
}

func (s *Scanner) FinishState() {
	s.states.Pop()
}

func compile(patterns []*pattern) (*dfapkg.DFA, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("No patterns added")
	}
	lexast, err := assembleAST(patterns)
	if err != nil {
		return nil, err
	}
	dfa := dfapkg.Generate(lexast)
	return dfa, nil
}

func assembleAST(patterns []*pattern) (frontend.AST, error) {
	asts := make([]frontend.AST, 0, len(patterns))
	for _, p := range patterns {
		ast, err := frontend.Parse(p.regex)
		if err != nil {
			return nil, err
		}
		asts = append(asts, ast)
	}
	lexast := asts[len(asts)-1]
	for i := len(asts) - 2; i >= 0; i-- {
		lexast = frontend.NewAltMatch(asts[i], lexast)
	}
	return lexast, nil
}

func (s *Scanner) Token(typ int, m *machines.Match, values ...interface{}) *Token {
	return &Token{
		Type:        typ,
		Value:       values,
		Lexeme:      m.Bytes,
		TC:          m.TC,
		StartLine:   m.StartLine,
		StartColumn: m.StartColumn,
		EndLine:     m.EndLine,
		EndColumn:   m.EndColumn,
	}
}

type Token struct {
	Type        int
	Value       []interface{}
	Lexeme      []byte
	TC          int
	StartLine   int
	StartColumn int
	EndLine     int
	EndColumn   int
}

// Equals checks the equality of two tokens ignoring the Value field.
func (t *Token) Equals(other *Token) bool {
	if t == nil && other == nil {
		return true
	} else if t == nil {
		return false
	} else if other == nil {
		return false
	}
	return t.TC == other.TC &&
		t.StartLine == other.StartLine &&
		t.StartColumn == other.StartColumn &&
		t.EndLine == other.EndLine &&
		t.EndColumn == other.EndColumn &&
		bytes.Equal(t.Lexeme, other.Lexeme) &&
		t.Type == other.Type
}

// String formats the token in a human readable form.
func (t *Token) String() string {
	return fmt.Sprintf("%d %q %d (%d, %d)-(%d, %d)", t.Type, t.Value, t.TC, t.StartLine, t.StartColumn, t.EndLine, t.EndColumn)
}
