package variables

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

type merger struct {
	variables []modsecurity.Variable
}

func (m *merger) Include(s string) error {
	for _, v := range m.variables {
		if err := v.Include(s); err != nil {
			return err
		}
	}
	return nil
}

func (m *merger) Exclude(s string) error {
	for _, v := range m.variables {
		if err := v.Exclude(s); err != nil {
			return err
		}
	}
	return nil
}

func (m *merger) Fetch(t *modsecurity.Transaction) []string {
	var res []string
	for _, v := range m.variables {
		res = append(res, v.Fetch(t)...)
	}
	return res
}
