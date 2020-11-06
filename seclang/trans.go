package seclang

import (
	"fmt"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/modsecurity/transforms"
	"github.com/hsluoyz/modsecurity-go/seclang/parser"
)

var transFactorys map[int]transFactory = map[int]transFactory{
	parser.TkTransLowercase:          transNoArgErrWrapper(transforms.NewTransLowerCase),
	parser.TkTransUrlDecode:          transNoArgErrWrapper(transforms.NewTransUrlDecode),
	parser.TkTransUrlDecodeUni:       transNoArgErrWrapper(transforms.NewTransUrlDecodeUni),
	parser.TkTransNone:               transNoArgErrWrapper(transforms.NewTransNone),
	parser.TkTransRemoveWhitespace:   transNoArgErrWrapper(transforms.NewTransRemoveWhitespace),
	parser.TkTransRemoveNulls:        transNoArgErrWrapper(transforms.NewTransRemoveNulls),
	parser.TkTransReplaceNulls:       transNoArgErrWrapper(transforms.NewTransReplaceNulls),
	parser.TkTransCompressWhitespace: transNoArgErrWrapper(transforms.NewTransCompressWhitespace),
}

func transNoArgErrWrapper(f func() modsecurity.Trans) func(v *parser.Trans) (modsecurity.Trans, error) {
	return func(v *parser.Trans) (modsecurity.Trans, error) {
		return f(), nil
	}
}

type transFactory func(*parser.Trans) (modsecurity.Trans, error)

func (dr *DireRule) applyTrans(transes []*parser.Trans) error {
	for _, trans := range transes {
		factory, has := transFactorys[trans.Tk]
		if !has {
			return fmt.Errorf("transform function %d is not implemented", trans.Tk)
		}
		a, err := factory(trans)
		if err != nil {
			return err
		}
		dr.rule.Trans = append(dr.rule.Trans, a)
	}
	return nil
}
