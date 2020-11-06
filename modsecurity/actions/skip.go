package actions

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

type ActionSkip struct {
}

func NewActionSkip() modsecurity.Action {
	return &ActionSkip{}
}
func (*ActionSkip) ActionGroup() int {
	return modsecurity.ActionGroupFlow
}

func (*ActionSkip) Name() string {
	return "skip"
}
func (a *ActionSkip) Value() string {
	return ""

}
func (a *ActionSkip) Do(t *modsecurity.Transaction) {
	t.JumpTo(t.CurrentRule() + 2)
}
