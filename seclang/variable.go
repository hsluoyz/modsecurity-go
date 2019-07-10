package seclang

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/modsecurity/variables"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

var variableFactorys map[int]VariableFactory = map[int]VariableFactory{
	parser.TkVarArgs:                  variableNoArgErrWrapper(variables.NewVariableArgs),
	parser.TkVarArgsNames:             variableNoArgErrWrapper(variables.NewVariableArgsNames),
	parser.TkVarArgsGet:               variableNoArgErrWrapper(variables.NewVariableArgsGet),
	parser.TkVarArgsGetNames:          variableNoArgErrWrapper(variables.NewVariableArgsGetNames),
	parser.TkVarArgsPost:              variableNoArgErrWrapper(variables.NewVariableArgsPost),
	parser.TkVarArgsPostNames:         variableNoArgErrWrapper(variables.NewVariableArgsPostNames),
	parser.TkVarQueryString:           variableNoArgErrWrapper(variables.NewVariableQueryString),
	parser.TkVarRemoteAddr:            variableNoArgErrWrapper(variables.NewVariableRemoteAddr),
	parser.TkVarRequestBasename:       variableNoArgErrWrapper(variables.NewVariableRequestBasename),
	parser.TkVarRequestBody:           variableNoArgErrWrapper(variables.NewVariableRequestBody),
	parser.TkVarRequestCookies:        variableNoArgErrWrapper(variables.NewVariableRequestCookies),
	parser.TkVarRequestCookiesNames:   variableNoArgErrWrapper(variables.NewVariableRequestCookiesNames),
	parser.TkVarRequestFilename:       variableNoArgErrWrapper(variables.NewVariableRequestFilename),
	parser.TkVarRequestHeaders:        variableNoArgErrWrapper(variables.NewVariableRequestHeaders),
	parser.TkVarRequestHeadersNames:   variableNoArgErrWrapper(variables.NewVariableRequestHeadersNames),
	parser.TkVarRequestMethod:         variableNoArgErrWrapper(variables.NewVariableRequestMethod),
	parser.TkVarRequestProtocol:       variableNoArgErrWrapper(variables.NewVariableRequestProtocol),
	parser.TkVarRequestUri:            variableNoArgErrWrapper(variables.NewVariableRequestURI),
	parser.TkVarResponseBody:          variableNoArgErrWrapper(variables.NewVariableResponseBody),
	parser.TkVarResponseContentLength: variableNoArgErrWrapper(variables.NewVariableResponseContentLength),
	parser.TkVarResponseContentType:   variableNoArgErrWrapper(variables.NewVariableResponseContentType),
	parser.TkVarResponseHeaders:       variableNoArgErrWrapper(variables.NewVariableResponseHeaders),
	parser.TkVarResponseHeadersNames:  variableNoArgErrWrapper(variables.NewVariableResponseHeadersNames),
	parser.TkVarResponseProtocol:      variableNoArgErrWrapper(variables.NewVariableResponseProtocol),
	parser.TkVarResponseStatus:        variableNoArgErrWrapper(variables.NewVariableResponseStatus),
}

func variableNoArgErrWrapper(f func() modsecurity.Variable) func(v *parser.Variable) (modsecurity.Variable, error) {
	return func(v *parser.Variable) (modsecurity.Variable, error) {
		return f(), nil
	}
}

type VariableFactory func(*parser.Variable) (modsecurity.Variable, error)

func (dr *DireRule) applyVariables(vs []*parser.Variable) error {
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
			return fmt.Errorf("variable %d is not implemented", v.Tk)
		}
		if !v.Count {
			if variable, has = varMap[v.Tk]; !has {
				if variable, err = factory(v); err != nil {
					return err
				}
				varMap[v.Tk] = variable
			}
		} else {
			if variable, has = countVarMap[v.Tk]; !has {
				if variable, err = factory(v); err != nil {
					return err
				}
				countVarMap[v.Tk] = variables.NewCountVariable(variable)
			}
		}
		if v.Index != "" {
			if !v.Exclusion {
				err := variable.Include(v.Index)
				if err != nil {
					return err
				}
			} else {
				err := variable.Exclude(v.Index)
				if err != nil {
					return err
				}
			}
		}
	}
	for _, variable := range varMap {
		dr.rule.Variables = append(dr.rule.Variables, variable)
	}
	for _, variable := range countVarMap {
		dr.rule.Variables = append(dr.rule.Variables, variable)
	}
	return nil
}
