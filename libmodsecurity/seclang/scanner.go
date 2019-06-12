// Thanks to the go-lua project. The scanner referenced some of the go-lua scanner implementations. https://github.com/Shopify/go-lua
package seclang

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

const (
	// begin of stream
	BOS = -1
	// end of stream
	EOS = -2
)

var escapes map[rune]rune = map[rune]rune{
	'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v', '\\': '\\', '"': '"', '\'': '\'',
}

type Directive interface {
	Type() int
}

type State struct {
	// Code: State code.
	Code int
	// ExitRunes: Exit current state when rune appear.
	ExitRunes []rune
	// Count: Number of token in current state.
	Count int
}

type Scanner struct {
	buffer               *bytes.Buffer
	r                    io.ByteReader
	current              rune
	LineNumber, LastLine int
}

func NewSecLangScanner(r io.ByteReader) *Scanner {
	return &Scanner{
		buffer:     bytes.NewBuffer(nil),
		r:          r,
		LastLine:   1,
		LineNumber: 1,
		current:    BOS,
	}
}

func (s *Scanner) ScanDirective() (Directive, error) {
	if s.current == BOS {
		s.advance()
	}
	for {
		switch c := s.current; c {
		case '\n', '\r':
			s.incrementLineNumber()
		case ' ', '\f', '\t', '\v':
			s.advance()
		case 0:
			s.advance()
		default:
			if s.StartsWith("sec") {
				return s.readDirective()
			}
			return nil, fmt.Errorf("expect directive got string `%s`", s.buffer.String())
		}
	}
}

func (s *Scanner) readDirective() (Directive, error) {
	dir := s.ReadWord()
	td := DirectiveFromString(dir)
	if td == nil {
		return nil, fmt.Errorf("string %s is not directive", dir)
	}
	return td.Func(s)
}

func (s *Scanner) ReadWord() string {
	for {
		if isAlphabet(s.current) {
			s.saveAndAdvance()
		} else {
			str := s.buffer.String()
			s.buffer.Reset()
			return str
		}
	}
}

func (s *Scanner) ReadString() (string, error) {
	for isBlank(s.current) {
		s.advance()
	}
	if s.current == '"' {
		return s.readString('"')
	}
	return s.readString(' ', '\f', '\t', '\v', '\n', '\r', EOS)
}

func (s *Scanner) readString(delimiter ...rune) (string, error) {
	if runeInSlice(s.current, delimiter) {
		s.advance()
	} else {
		s.saveAndAdvance()
	}
	for !runeInSlice(s.current, delimiter) {
		switch s.current {
		case EOS:
			return "", errors.New("unfinished string got EOS")
		case '\n', '\r':
			return "", errors.New("unfinished string got newline")
		case '\\':
			s.advance()
			c := s.current
			switch esc, ok := escapes[c]; {
			case ok:
				s.advanceAndSave(esc)
			case isNewLine(c):
				s.incrementLineNumber()
				s.save('\n')
			case c == EOS: // do nothing
			default:
				s.saveAndAdvance()
			}
		default:
			s.saveAndAdvance()
		}
	}

	s.advance()
	str := s.buffer.String()
	s.buffer.Reset()
	return str, nil
}

func (s *Scanner) ReadValue(tks ...int) (int, string, error) {
	var expected []string
	str, err := s.ReadString()
	if err != nil {
		return 0, "", err
	}
	for _, tk := range tks {
		v, ok := Values[tk]
		if !ok {
			return 0, "", fmt.Errorf("value token %d not found", tk)
		}
		if v.regex.MatchString(str) {
			return tk, str, nil
		}
		expected = append(expected, v.Regex)
	}

	return 0, "", fmt.Errorf("expect %s got %s", strings.Join(expected, "|"), str)
}

func (s *Scanner) StartsWith(str string) bool {
	for _, r := range str {
		if unicode.ToLower(s.current) == unicode.ToLower(r) {
			s.saveAndAdvance()
			continue
		}
		return false
	}
	return true
}

func (s *Scanner) incrementLineNumber() {
	old := s.current
	if s.advance(); isNewLine(s.current) && s.current != old {
		s.advance()
	}
	s.LineNumber++
}

func (s *Scanner) advance() {
	if c, err := s.r.ReadByte(); err != nil {
		s.current = EOS
	} else {
		s.current = rune(c)
	}
}

func (s *Scanner) saveAndAdvance() {
	s.save(s.current)
	s.advance()
}

func (s *Scanner) advanceAndSave(c rune) {
	s.advance()
	s.save(c)
}
func (s *Scanner) save(c rune) {
	s.buffer.WriteByte(byte(c))
}
