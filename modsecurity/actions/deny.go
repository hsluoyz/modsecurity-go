package actions

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

type ActionDeny struct{}

func NewActionDeny() modsecurity.Action {
	return &ActionDeny{}
}
func (*ActionDeny) ActionGroup() int {
	return modsecurity.ActionGroupDisruptive
}

func (*ActionDeny) Name() string {
	return "deny"
}
func (*ActionDeny) Value() string {
	return ""

}
func (*ActionDeny) Do(t *modsecurity.Transaction) {
	i := t.Intervention()
	if i.Status == 200 {
		var status int
		if s, ok := t.Data["status"].(int); ok {
			status = s
		}
		if status >= 100 && status <= 599 {
			i.Status = status
		} else {
			i.Status = 403
		}

	}
	i.Disruptive = true
	t.Logf("ModSecurity: Access denied with code 403")
}
