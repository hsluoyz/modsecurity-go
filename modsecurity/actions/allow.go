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

func (*ActionAllow) Name() string {
	return "allow"
}
func (a *ActionAllow) Value() string {
	return a.arg

}
func (a *ActionAllow) Do(t *modsecurity.Transaction) {
	i := t.Intervention()
	if i.Status == 200 {
		i.Status = 403
	}
	i.Disruptive = true
	t.Logf("ModSecurity: Access denied with code 403")
}
