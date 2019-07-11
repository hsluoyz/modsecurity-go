package operators

import (
	"regexp"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewOperatorRx(re string) (modsecurity.Operator, error) {
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
func (o *OperatorRx) Match(tr *modsecurity.Transaction, s string) bool {
	return o.match.MatchString(s)
}
