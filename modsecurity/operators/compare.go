package operators

import (
	"strconv"
	"strings"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewOperatorEq(arg string) (modsecurity.Operator, error) {
	return newOperatorCompare("eq", arg, func(v int64, arg int64) bool {
		return v == arg
	})
}
func NewOperatorGe(arg string) (modsecurity.Operator, error) {
	return newOperatorCompare("ge", arg, func(v int64, arg int64) bool {
		return v >= arg
	})
}
func NewOperatorGt(arg string) (modsecurity.Operator, error) {
	return newOperatorCompare("gt", arg, func(v int64, arg int64) bool {
		return v > arg
	})
}
func NewOperatorLe(arg string) (modsecurity.Operator, error) {
	return newOperatorCompare("le", arg, func(v int64, arg int64) bool {
		return v <= arg
	})
}
func NewOperatorLt(arg string) (modsecurity.Operator, error) {
	return newOperatorCompare("lt", arg, func(v int64, arg int64) bool {
		return v < arg
	})
}

func newOperatorCompare(name, arg string, fn func(v, arg int64) bool) (modsecurity.Operator, error) {
	arg = strings.TrimSpace(arg)
	v, err := strconv.ParseInt(arg, 10, 64)
	if err != nil {
		return nil, err
	}
	return &OperatorCompare{
		fn:        fn,
		arg:       v,
		argString: arg,
		name:      name,
	}, nil
}

type OperatorCompare struct {
	fn        func(v, in int64) bool
	arg       int64
	argString string
	name      string
}

func (o *OperatorCompare) Name() string {
	return o.name
}
func (o *OperatorCompare) Args() string {
	return o.argString
}

func (o *OperatorCompare) Match(tr *modsecurity.Transaction, s string) bool {
	s = strings.TrimSpace(s)
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		v = 0
	}
	return o.fn(v, o.arg)
}
