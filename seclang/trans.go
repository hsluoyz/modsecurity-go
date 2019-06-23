package seclang

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

var transFactorys map[int]TransFactory = map[int]TransFactory{
	parser.TkTransLowercase: transNoArgErrWrapper(modsecurity.NewTransLowerCase),
}

func transNoArgErrWrapper(f func() modsecurity.Trans) func(v *parser.Trans) (modsecurity.Trans, error) {
	return func(v *parser.Trans) (modsecurity.Trans, error) {
		return f(), nil
	}
}

type TransFactory func(*parser.Trans) (modsecurity.Trans, error)

func MakeTrans(transes []*parser.Trans) ([]modsecurity.Trans, error) {
	var res []modsecurity.Trans
	for _, trans := range transes {
		factory, has := transFactorys[trans.Tk]
		if !has {
			return nil, fmt.Errorf("transform function %d is not implemented", trans.Tk)
		}
		a, err := factory(trans)
		if err != nil {
			return nil, err
		}
		res = append(res, a)
	}
	return res, nil
}
