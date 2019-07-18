package actions

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

type ActionAllow struct {
	arg string
}

func NewActionAllow(arg string) modsecurity.Action {
	return &ActionAllow{
		arg: arg,
	}
}
func (*ActionAllow) ActionGroup() int {
	return modsecurity.ActionGroupDisruptive
}

func (*ActionAllow) Name() string {
	return "allow"
}
func (a *ActionAllow) Value() string {
	return a.arg

}
func (a *ActionAllow) Do(t *modsecurity.Transaction) {
	switch a.arg {
	case "":
		t.JumpToPhase(modsecurity.PhaseLogging)
	case "phase":
		t.NextPhase()
	case "request":
		t.JumpToPhase(modsecurity.PhaseResponseHeaders)
	}
}
