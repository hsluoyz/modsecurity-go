package variables

import (
	"strconv"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewCountVariable(v modsecurity.Variable) modsecurity.Variable {
	return &CountVariable{v}
}

type CountVariable struct {
	modsecurity.Variable
}

func (v *CountVariable) Fetch(t *modsecurity.Transaction) []string {
	return []string{strconv.Itoa(len(v.Variable.Fetch(t)))}
}
