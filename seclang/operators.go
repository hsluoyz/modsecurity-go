package seclang

import (
	"fmt"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/modsecurity/operators"
	"github.com/hsluoyz/modsecurity-go/seclang/parser"
)

var operatorFactorys map[int]operatorFactory = map[int]operatorFactory{
	parser.TkOpRx: operatorWrapper(operators.NewOperatorRx),
	parser.TkOpEq: operatorWrapper(operators.NewOperatorEq),
	parser.TkOpGt: operatorWrapper(operators.NewOperatorGt),
	parser.TkOpGe: operatorWrapper(operators.NewOperatorGe),
	parser.TkOpLt: operatorWrapper(operators.NewOperatorLt),
	parser.TkOpLe: operatorWrapper(operators.NewOperatorLe),
}

func operatorWrapper(f func(string) (modsecurity.Operator, error)) func(v *parser.Operator) (modsecurity.Operator, error) {
	return func(v *parser.Operator) (modsecurity.Operator, error) {
		return f(v.Argument)
	}
}

type operatorFactory func(*parser.Operator) (modsecurity.Operator, error)

func (dr *DireRule) applyOperator(o *parser.Operator) error {
	var err error
	factory, has := operatorFactorys[o.Tk]
	if !has {
		return fmt.Errorf("variable %d is not implemented", o.Tk)
	}
	dr.rule.Operator, err = factory(o)
	if err != nil {
		return err
	}
	dr.rule.Not = o.Not
	return nil
}
