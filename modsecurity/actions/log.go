package actions

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

type ActionLog struct{}

func NewActionLog() modsecurity.Action {
	return &ActionLog{}
}

func (*ActionLog) ActionGroup() int {
	return modsecurity.ActionGroupNonDisruptive
}
func (*ActionLog) Name() string {
	return "log"
}
func (*ActionLog) Value() string {
	return ""

}
func (*ActionLog) Do(t *modsecurity.Transaction) {
	t.Logf("ModSecurity: running action in phase %d rule %d", t.CurrentPhase(), t.CurrentRule())
}
