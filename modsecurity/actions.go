package modsecurity

type Action interface {
	Name() string
	Value() string
	Do(*Transaction)
}

type ActionDeny struct{}

func NewActionDeny() Action {
	return &ActionDeny{}
}

func (*ActionDeny) Name() string {
	return "deny"
}
func (*ActionDeny) Value() string {
	return ""

}
func (*ActionDeny) Do(t *Transaction) {
	i := t.Intervention()
	if i.Status == 200 {
		i.Status = 403
	}
	i.Disruptive = true
	t.Logf("ModSecurity: Access denied with code 403")
}
