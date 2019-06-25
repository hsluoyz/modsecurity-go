package seclang

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

var variableFactorys map[int]VariableFactory = map[int]VariableFactory{
	parser.TkVarRequestUri: variableNoArgErrWrapper(modsecurity.NewVariableRequestURI),
	parser.TkVarArgsGet:    variableNoArgErrWrapper(modsecurity.NewVariableArgsGet),
}

func variableNoArgErrWrapper(f func() modsecurity.Variable) func(v *parser.Variable) (modsecurity.Variable, error) {
	return func(v *parser.Variable) (modsecurity.Variable, error) {
		return f(), nil
	}
}

type VariableFactory func(*parser.Variable) (modsecurity.Variable, error)

func MakeVariables(vs []*parser.Variable) ([]modsecurity.Variable, error) {
	var (
		has      bool
		err      error
		factory  VariableFactory
		variable modsecurity.Variable
	)
	varMap := make(map[int]modsecurity.Variable)
	countVarMap := make(map[int]modsecurity.Variable)
	for _, v := range vs {
		factory, has = variableFactorys[v.Tk]
		if !has {
			return nil, fmt.Errorf("variable %d is not implemented", v.Tk)
		}
		if !v.Count {
			if variable, has = varMap[v.Tk]; !has {
				if variable, err = factory(v); err != nil {
					return nil, err
				}
				varMap[v.Tk] = variable
			}
		} else {
			if variable, has = countVarMap[v.Tk]; !has {
				if variable, err = factory(v); err != nil {
					return nil, err
				}
				countVarMap[v.Tk] = modsecurity.NewCountVariable(variable)
			}
		}
		if v.Index != "" {
			if !v.Exclusion {
				err := variable.Include(v.Index)
				if err != nil {
					return nil, err
				}
			} else {
				err := variable.Exclude(v.Index)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	var res []modsecurity.Variable
	for _, variable := range varMap {
		res = append(res, variable)
	}
	for _, variable := range countVarMap {
		res = append(res, variable)
	}
	return res, nil
}
