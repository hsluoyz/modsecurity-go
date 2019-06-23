// Seclang Parser.
// Thanks to the go-lua project. The scanner referenced some of the go-lua scanner implementations. https://github.com/Shopify/go-lua
package parser

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
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

var ErrEOS = errors.New("EOS")

type Directive interface {
	Token() int
}

type Scanner struct {
	buffer               *bytes.Buffer
	r                    *bufio.Reader
	current              rune
	LineNumber, LastLine int
}

func NewSecLangScanner(r io.Reader) *Scanner {
	return &Scanner{
		buffer:     bytes.NewBuffer(nil),
		r:          bufio.NewReader(r),
		LastLine:   1,
		LineNumber: 1,
		current:    BOS,
	}
}

func NewSecLangScannerFromString(s string) *Scanner {
	return NewSecLangScanner(strings.NewReader(s))
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
	s.SkipBlank()
	if isNewLine(s.current) {
		s.incrementLineNumber()
		return "", nil
	}
	if s.current == '"' {
		return s.readString('"')
	}
	if s.current == '\'' {
		return s.readString('\'')
	}
	if s.current == EOS {
		return "", ErrEOS
	}
	return s.readString(' ', '\f', '\t', '\v', '\n', '\r', EOS)
}

func (s *Scanner) readString(delimiter ...rune) (string, error) {
	if runeInSlice(s.current, delimiter) {
		s.advance()
	}
	for !runeInSlice(s.current, delimiter) {
		switch s.current {
		case EOS:
			if s.buffer.Len() > 0 {
				return "", fmt.Errorf("unexpected EOS after %s", s.buffer.String())
			}
			return "", nil
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
			case c == EOS:
				return "", fmt.Errorf("unexpected EOS after %s", s.buffer.String())
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

func (s *Scanner) ReadDirective() (Directive, error) {
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
		case EOS:
			return nil, ErrEOS
		default:
			dir, err := s.readDirective()
			if err == ErrEOS {
				return nil, errors.New("unexpected EOS")
			}
			return dir, err
		}
	}
}

func (s *Scanner) AllDirective() ([]Directive, error) {
	var dirs []Directive
	for {
		d, err := s.ReadDirective()
		if err == ErrEOS {
			break
		}
		if err != nil {
			return nil, err
		}
		dirs = append(dirs, d)
	}
	return dirs, nil
}

func (s *Scanner) readDirective() (Directive, error) {
	dir := s.ReadWord()
	td := DirectiveFromString(dir)
	if td == nil {
		return nil, fmt.Errorf("string %s is not directive", dir)
	}
	return td.Func(s)
}

func (s *Scanner) ReadVariables() ([]*Variable, error) {
	res := make([]*Variable, 0, 1)
	argString, err := s.ReadString()
	if err != nil {
		return nil, err
	}
	if len(argString) == 0 {
		return nil, errors.New("expected variable bug got empty")
	}

	args := splitMulti(argString, ",|")
	for _, a := range args {
		if len(a) < 1 {
			return nil, errors.New("unexpected ',' or '|' in argument")
		}
		arg := &Variable{}
		if a[0] == '!' {
			arg.Exclusion = true
			a = a[1:]
		} else if a[0] == '&' {
			arg.Count = true
			a = a[1:]
		}
		i := strings.IndexAny(a, ".:")
		if i > 0 {
			arg.Index = a[i+1:]
			a = a[:i]
		}
		tk, has := variableMap[a]
		if !has {
			return nil, fmt.Errorf("unknown variable %s\n", a)
		}
		arg.Tk = tk
		res = append(res, arg)
	}

	return res, nil
}

func (s *Scanner) ReadOperator() (*Operator, error) {
	res := new(Operator)
	opString, err := s.ReadString()
	if err != nil {
		return nil, err
	}
	if len(opString) == 0 {
		return nil, errors.New("expected operator bug got empty")
	}
	if len(opString) > 0 && opString[0] == '!' {
		res.Not = true
		opString = opString[1:]
	}
	if len(opString) == 0 {
		return nil, fmt.Errorf("expecting operator bug get %s", opString)
	}
	if opString[0] != '@' {
		res.Tk = TkOpRx
		res.Argument = opString
		return res, nil
	}
	opWithArg := strings.SplitN(opString, " ", 2)
	op := opWithArg[0]
	if len(opWithArg) > 1 {
		res.Argument = opWithArg[1]
	}
	if op[0] != '@' {
		return nil, errors.New("operator must begin with @")
	}
	op = op[1:] // skip @
	tk, has := operatorMap[op]
	if !has {
		return nil, fmt.Errorf("expect operator got @%s", op)
	}
	res.Tk = tk
	return res, nil
}

func (s *Scanner) ReadActions() (*Actions, error) {
	res := new(Actions)
	str, err := s.ReadString()
	if err != nil {
		return nil, err
	}
	str = strings.TrimSpace(str)
	// str = strings.Trim(str, "\r\n\t\f\v ")
	if len(str) == 0 {
		return nil, errors.New("expected actions bug got empty")
	}
	acts := strings.Split(str, ",")
	for _, act := range acts {
		switch tk, arg, err := parseAction(act); tk {
		case 0:
			return nil, err
		case TkActionId:
			arg = trimQuote(arg)
			res.Id, err = strconv.Atoi(arg)
			if err != nil {
				return nil, fmt.Errorf("cannot parse id %s, err: %s", arg, err.Error())
			}
		case TkActionSeverity:
			arg = trimQuote(arg)
			if severity, has := severityMap[arg]; has {
				res.Action = append(res.Action, &Action{tk, strconv.Itoa(severity)})
			} else if severity, err := strconv.Atoi(arg); err == nil && severity >= 0 && severity <= 7 {
				res.Action = append(res.Action, &Action{tk, strconv.Itoa(severity)})
			} else {
				return nil, fmt.Errorf("unknown severity %s", arg)
			}
		case TkActionT:
			arg = trimQuote(arg)
			if tt, has := transformationMap[arg]; has {
				res.Trans = append(res.Trans, &Trans{tt})
			} else {
				return nil, fmt.Errorf("unknown trans formation %s", arg)
			}
		case TkActionPhase:
			arg = trimQuote(arg)
			p, has := phaseAlias[arg]
			if has {
				res.Phase = p
				continue
			}
			p, err = strconv.Atoi(arg)
			if err != nil {
				return nil, fmt.Errorf("cannot parse phase %s, err: %s", arg, err.Error())
			}
			if p < PhaseRequestHeaders || p > PhaseLogging {
				return nil, fmt.Errorf("unsupported phase %d", p)
			}
			res.Phase = p
		case TkActionTag, TkActionMsg:
			arg = trimQuote(arg)
			res.Action = append(res.Action, &Action{tk, arg})
		default:
			res.Action = append(res.Action, &Action{tk, arg})
		}
	}
	return res, nil
}

func parseAction(act string) (int, string, error) {
	var arg string
	s := strings.SplitN(act, ":", 2)
	action := strings.TrimSpace(s[0])
	tk, has := actionMap[action]
	if !has {
		return 0, "", fmt.Errorf("unknown action %s", s[0])
	}
	if len(s) > 1 {
		arg = s[1]
	}
	return tk, arg, nil
}

func (s *Scanner) SkipBlank() error {
	for {
		switch {
		case s.current == BOS:
			s.advance()
		case isBlank(s.current):
			s.advance()
		case s.current == '\\':
			if s.next() == '\n' {
				s.advance()             //skip '\\'
				s.incrementLineNumber() // skip newlines

			}
		default:
			return nil

		}
	}
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

func (s *Scanner) next() rune {
	if c, err := s.r.ReadByte(); err != nil {
		return EOS
	} else {
		s.r.UnreadByte()
		return rune(c)
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

type StringArgDirective struct {
	Tk    int
	Value string
}

func (d *StringArgDirective) Token() int {
	return d.Tk
}

func StringArgDirectiveFactory(tk int) DirectiveFactory {
	return func(s *Scanner) (Directive, error) {
		str, err := s.ReadString()
		if err != nil {
			return nil, err
		}
		return &StringArgDirective{
			Tk:    tk,
			Value: str,
		}, nil
	}
}

type BoolArgDirective struct {
	Tk    int
	Value bool
}

func (d *BoolArgDirective) Token() int {
	return d.Tk
}

func BoolArgDirectiveFactory(tk int) DirectiveFactory {
	return func(s *Scanner) (Directive, error) {
		tkVal, _, err := s.ReadValue(TkValueOn, TkValueOff)
		if err != nil {
			return nil, err
		}
		return &BoolArgDirective{
			Tk:    tk,
			Value: tkVal == TkValueOn,
		}, nil
	}
}

const (
	TriBoolTrue  = 1
	TriBoolElse  = 2
	TriBoolFalse = 0
)

type TriBoolArgDirective struct {
	Tk    int
	Value int // 1: on; 2: DetectionOnly; 0: off
}

func (d *TriBoolArgDirective) Token() int {
	return d.Tk
}

func TriBoolArgDirectiveFactory(tk int) DirectiveFactory {
	val := map[int]int{
		TkValueOn:   TriBoolTrue,
		TkValueElse: TriBoolElse,
		TkValueOff:  TriBoolFalse,
	}
	return func(s *Scanner) (Directive, error) {
		tkVal, _, err := s.ReadValue(TkValueOn, TkValueOff, TkValueElse)
		if err != nil {
			return nil, err
		}
		return &TriBoolArgDirective{
			Tk:    tk,
			Value: val[tkVal],
		}, nil
	}
}

type Variable struct {
	Tk        int
	Index     string
	Count     bool
	Exclusion bool
}

type Operator struct {
	Tk       int
	Not      bool
	Argument string
}

type Action struct {
	Tk       int
	Argument string
}
type Trans struct {
	Tk int
}

type Actions struct {
	Id     int
	Phase  int
	Trans  []*Trans
	Action []*Action
}

type RuleDirective struct {
	Variable []*Variable
	Operator *Operator
	Actions  *Actions
}

func (d *RuleDirective) Token() int {
	return TkDirRule
}

func RuleDirectiveScaner(s *Scanner) (Directive, error) {
	rule := &RuleDirective{}
	vars, err := s.ReadVariables()
	if err != nil {
		return nil, err
	}
	rule.Variable = vars
	op, err := s.ReadOperator()
	if err != nil {
		return nil, err
	}
	rule.Operator = op
	actions, err := s.ReadActions()
	if err != nil {
		return nil, err
	}
	rule.Actions = actions
	return rule, nil
}
