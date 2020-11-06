package actions

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

type ActionPass struct{}

func NewActionPass() modsecurity.Action {
	return &ActionPass{}
}
func (*ActionPass) ActionGroup() int {
	return modsecurity.ActionGroupDisruptive
}

func (*ActionPass) Name() string {
	return "pass"
}
func (*ActionPass) Value() string {
	return ""

}
func (*ActionPass) Do(t *modsecurity.Transaction) {
	t.ResetIntervention()
}
