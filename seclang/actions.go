package seclang

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/modsecurity/actions"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

var actionFactorys map[int]ActionFactory = map[int]ActionFactory{
	parser.TkActionDeny: actionNoArgErrWrapper(actions.NewActionDeny),
}

func actionNoArgErrWrapper(f func() modsecurity.Action) func(v *parser.Action) (modsecurity.Action, error) {
	return func(v *parser.Action) (modsecurity.Action, error) {
		return f(), nil
	}
}

type ActionFactory func(*parser.Action) (modsecurity.Action, error)

func MakeActions(actions []*parser.Action) ([]modsecurity.Action, error) {
	var res []modsecurity.Action
	for _, action := range actions {
		factory, has := actionFactorys[action.Tk]
		if !has {
			return nil, fmt.Errorf("variable %d is not implemented", action.Tk)
		}
		a, err := factory(action)
		if err != nil {
			return nil, err
		}
		res = append(res, a)
	}
	return res, nil
}
