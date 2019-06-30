package variables

import (
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/utils"
)

type variableConst struct {
	vars []string
	*filter
}

func (v *variableConst) Name() string {
	return "CONST"
}
func (v *variableConst) Fetch(t *modsecurity.Transaction) []string {
	vars := make(map[string][]string)
	for _, v := range v.vars {
		vars[v] = []string{v}
	}
	return v.filter.Fetch(vars)
}

func TestMerger(t *testing.T) {
	input1 := []string{"v111", "v112"}
	input2 := []string{"v211", "v212"}
	newMerger := func() *merger {
		v1 := &variableConst{
			vars:   input1,
			filter: &filter{},
		}
		v2 := &variableConst{
			vars:   input2,
			filter: &filter{},
		}
		return &merger{
			variables: []modsecurity.Variable{v1, v2},
		}
	}
	t.Run("all", func(t *testing.T) {
		m := newMerger()
		res := m.Fetch(nil)
		if !utils.SameStringSlice(res, []string{
			"v111", "v112",
			"v211", "v212",
		}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})

	t.Run("include", func(t *testing.T) {
		m := newMerger()
		m.Include(`/v[0-9]11/`)
		res := m.Fetch(nil)
		if !utils.SameStringSlice(res, []string{
			"v111", "v211",
		}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
	t.Run("exclude", func(t *testing.T) {
		m := newMerger()
		m.Exclude(`/v[0-9]{2}2/`)
		res := m.Fetch(nil)
		if !utils.SameStringSlice(res, []string{
			"v111", "v211",
		}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
