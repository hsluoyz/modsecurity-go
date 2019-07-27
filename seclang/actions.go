package seclang

import (
	"fmt"
	"strconv"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/modsecurity/actions"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

var actionFactorys map[int]*actionProcessor = map[int]*actionProcessor{
	parser.TkActionDeny: &actionProcessor{
		factory: actionWrapper(actions.NewActionDeny),
	},
	parser.TkActionSkip: &actionProcessor{
		factory: actionWrapper(actions.NewActionSkip),
	},
	parser.TkActionLog: &actionProcessor{
		factory: actionWrapper(actions.NewActionLog),
	},
	parser.TkActionBlock: &actionProcessor{
		factory: actionWrapper(actions.NewActionBlock),
	},
	parser.TkActionStatus: &actionProcessor{
		factory: actionNumArgWrapper(actions.NewActionStatus),
	},
	parser.TkActionAllow: &actionProcessor{
		factory: actionArgWrapper(actions.NewActionAllow),
	},
	parser.TkActionTag: &actionProcessor{
		meta: metaFactory("tag"),
	},
	parser.TkActionMsg: &actionProcessor{
		meta: metaFactory("msg"),
	},
	parser.TkActionRev: &actionProcessor{
		meta: metaFactory("rev"),
	},
	parser.TkActionVer: &actionProcessor{
		meta: metaFactory("ver"),
	},
}

func isQuote(c rune) bool { return '\'' == c || '"' == c }
func trimQuote(s string) string {
	if len(s) >= 2 && isQuote(rune(s[0])) && isQuote(rune(s[len(s)-1])) {
		return s[1 : len(s)-1]
	}
	return s
}

func toNum(s string) (int, error) {
	s = trimQuote(s)
	return strconv.Atoi(s)
}

func metaFactory(name string) func(*parser.Action) (map[string]string, error) {
	return func(parsed *parser.Action) (map[string]string, error) {
		res := make(map[string]string)
		res[name] = trimQuote(parsed.Argument)
		return res, nil
	}
}

func actionArgWrapper(f func(string) modsecurity.Action) func(v *parser.Action) (modsecurity.Action, error) {
	return func(v *parser.Action) (modsecurity.Action, error) {
		return f(trimQuote(v.Argument)), nil
	}
}
func actionNumArgWrapper(f func(int) modsecurity.Action) func(v *parser.Action) (modsecurity.Action, error) {
	return func(v *parser.Action) (modsecurity.Action, error) {
		arg, err := toNum(v.Argument)
		if err != nil {
			return nil, err
		}
		return f(arg), nil
	}
}

func actionWrapper(f func() modsecurity.Action) func(v *parser.Action) (modsecurity.Action, error) {
	return func(v *parser.Action) (modsecurity.Action, error) {
		return f(), nil
	}
}

type actionProcessor struct {
	meta    func(*parser.Action) (map[string]string, error)
	factory func(*parser.Action) (modsecurity.Action, error)
}

func (dr *DireRule) applyActions(actions *parser.Actions) error {
	dr.rule.Id = actions.Id
	dr.rule.Phase = actions.Phase
	dr.chain = actions.Chain
	for _, action := range actions.Action {
		processor, has := actionFactorys[action.Tk]
		if !has {
			return fmt.Errorf("variable %d is not implemented", action.Tk)
		}
		if processor.meta != nil {
			meta, err := processor.meta(action)
			if err != nil {
				return err
			}
			for k, v := range meta {
				dr.rule.MetaData[k] = append(dr.rule.MetaData[k], v)
			}
		}
		if processor.factory != nil {
			a, err := processor.factory(action)
			if err != nil {
				return err
			}
			dr.rule.Actions = append(dr.rule.Actions, a)
		}
	}
	return nil
}
