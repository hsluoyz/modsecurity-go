package actions

import (
	"strconv"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

type ActionStatus struct {
	status int
}

func NewActionStatus(status int) modsecurity.Action {
	return &ActionStatus{status}
}

func (*ActionStatus) ActionGroup() int {
	return modsecurity.ActionGroupData
}

func (*ActionStatus) Name() string {
	return "status"
}
func (a *ActionStatus) Value() string {
	return strconv.Itoa(a.status)

}
func (a *ActionStatus) Do(t *modsecurity.Transaction) {
	t.Data["status"] = a.status
}
