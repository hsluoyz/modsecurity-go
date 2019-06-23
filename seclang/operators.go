package seclang

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

var operatorFactorys map[int]OperatorFactory = map[int]OperatorFactory{
	parser.TkOpRx: operatorWrapper(modsecurity.NewOperatorRx),
}

func operatorWrapper(f func(string) (modsecurity.Operator, error)) func(v *parser.Operator) (modsecurity.Operator, error) {
	return func(v *parser.Operator) (modsecurity.Operator, error) {
		return f(v.Argument)
	}
}

type OperatorFactory func(*parser.Operator) (modsecurity.Operator, error)

func MakeOperator(o *parser.Operator) (modsecurity.Operator, error) {
	factory, has := operatorFactorys[o.Tk]
	if !has {
		return nil, fmt.Errorf("variable %d is not implemented", o.Tk)
	}
	return factory(o)
}
