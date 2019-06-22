package modsecurity

import "regexp"

type Operator interface {
	Name() string
	Args() string
	Match(string) bool
}

func NewOperatorRx(re string) (Operator, error) {
	match, err := regexp.Compile(re)
	if err != nil {
		return nil, err
	}
	return &OperatorRx{
		re:    re,
		match: match,
	}, nil
}

type OperatorRx struct {
	re    string
	match *regexp.Regexp
}

func (o *OperatorRx) Name() string {
	return "rx"
}
func (o *OperatorRx) Args() string {
	return o.re

}
func (o *OperatorRx) Match(s string) bool {
	return o.match.MatchString(s)
}
