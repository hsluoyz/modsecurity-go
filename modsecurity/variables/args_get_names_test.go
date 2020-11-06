package variables

import (
	"net/url"
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/utils"
)

func TestVariableArgsGetNames(t *testing.T) {
	v := NewVariableArgsGetNames()
	if v.Name() != "ARGS_GET_NAMES" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	vars := v.Fetch(nil)
	if vars != nil {
		t.Errorf("got unexcepted variable %#v ", vars)
	}
	t.Run("regex name", func(t *testing.T) {
		v := NewVariableArgsGetNames()
		v.Include(`/a/`)
		u, _ := url.Parse("http://localhost/query?a1=1&a2=2&b1=3&b2=4")

		tr, err := modsecurity.NewTransaction(modsecurity.NewEngine(), modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		tr.ProcessRequestURL(u, "GET", "HTTP/1.1")
		res := v.Fetch(tr)
		if !utils.SameStringSlice(res, []string{"a1", "a2"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
	t.Run("exclude name", func(t *testing.T) {
		v := NewVariableArgsGetNames()
		v.Exclude(`b1`)
		u, _ := url.Parse("http://localhost/query?a1=1&a2=2&b1=3&b2=4")
		tr, err := modsecurity.NewTransaction(modsecurity.NewEngine(), modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		tr.ProcessRequestURL(u, "GET", "HTTP/1.1")
		res := v.Fetch(tr)
		if !utils.SameStringSlice(res, []string{"a1", "a2", "b2"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
	t.Run("exclude regex name", func(t *testing.T) {
		v := NewVariableArgsGetNames()
		v.Exclude(`/^a/`)
		u, _ := url.Parse("http://localhost/query?a1=1&a2=2&b1=3&b2=4")
		tr, err := modsecurity.NewTransaction(modsecurity.NewEngine(), modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		tr.ProcessRequestURL(u, "GET", "HTTP/1.1")
		res := v.Fetch(tr)
		if !utils.SameStringSlice(res, []string{"b1", "b2"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
