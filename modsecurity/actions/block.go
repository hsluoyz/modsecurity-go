package actions

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

type ActionBlock struct{}

func NewActionBlock() modsecurity.Action {
	return &ActionBlock{}
}

func (*ActionBlock) Name() string {
	return "block"
}
func (*ActionBlock) Value() string {
	return ""

}
func (*ActionBlock) Do(t *modsecurity.Transaction) {
	if t.RuleSet == nil {
		return
	}
	for _, action := range t.RuleSet.DefaultActions {
		action.Do(t)
	}
}
