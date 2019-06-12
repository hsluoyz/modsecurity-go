package seclang

func init() {
	initDirectives()
}

func initDirectives() {
	// registerDir(TkDirRule, `SecRule`, StringDirectiveFactory(TkDirRule))
	registerDir(TkDirRuleEng, `SecRuleEngine`, TriBoolArgDirectiveFactory(TkDirRuleEng))
	registerDir(TkDirReqBody, `SecRequestBodyAccess`, BoolArgDirectiveFactory(TkDirReqBody))
	registerDir(TkDirResBody, `SecResponseBodyAccess`, BoolArgDirectiveFactory(TkDirResBody))
}

type StringArgDirective struct {
	kind  int
	Value string
}

func (d *StringArgDirective) Type() int {
	return d.kind
}

func StringArgDirectiveFactory(tk int) DirectiveFactory {
	return func(s *Scanner) (Directive, error) {
		str, err := s.ReadString()
		if err != nil {
			return nil, err
		}
		return &StringArgDirective{
			kind:  tk,
			Value: str,
		}, nil
	}
}

type BoolArgDirective struct {
	kind  int
	Value bool
}

func (d *BoolArgDirective) Type() int {
	return d.kind
}

func BoolArgDirectiveFactory(tk int) DirectiveFactory {
	return func(s *Scanner) (Directive, error) {
		tkVal, _, err := s.ReadValue(TkValueOn, TkValueOff)
		if err != nil {
			return nil, err
		}
		return &BoolArgDirective{
			kind:  tk,
			Value: tkVal == TkValueOn,
		}, nil
	}
}

const (
	TriBoolTrue  = 1
	TriBoolDetc  = 2
	TriBoolFalse = 0
)

type TriBoolArgDirective struct {
	kind  int
	Value int // 1: on; 2: DetectionOnly; 0: off
}

func (d *TriBoolArgDirective) Type() int {
	return d.kind
}

func TriBoolArgDirectiveFactory(tk int) DirectiveFactory {
	val := map[int]int{
		TkValueOn:   1,
		TkValueDetc: 2,
		TkValueOff:  0,
	}
	return func(s *Scanner) (Directive, error) {
		tkVal, _, err := s.ReadValue(TkValueOn, TkValueOff, TkValueDetc)
		if err != nil {
			return nil, err
		}
		return &TriBoolArgDirective{
			kind:  tk,
			Value: val[tkVal],
		}, nil
	}
}
