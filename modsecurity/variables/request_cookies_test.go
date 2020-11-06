package variables

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/utils"
)

func TestVariableRequestCookies(t *testing.T) {
	v := NewVariableRequestCookies()
	if v.Name() != "REQUEST_COOKIES" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	engine := modsecurity.NewEngine()
	t.Run("none cookies", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		u, _ := url.Parse("http://localhost/query")
		header := map[string][]string{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}
		tr.ProcessRequestURL(u, "POST", "HTTP/1.1")
		tr.ProcessRequestHeader(header)
		res := v.Fetch(tr)
		if len(res) != 0 {
			t.Errorf("variable args get fail got %q", res)
		}
	})
	t.Run("some cookies", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		u, _ := url.Parse("http://localhost/query")
		header := map[string][]string{
			"Cookie": []string{
				(&http.Cookie{Name: "abc", Value: "def"}).String(),
				(&http.Cookie{Name: "ghi", Value: "jkl"}).String(),
			},
		}
		tr.ProcessRequestURL(u, "POST", "HTTP/1.1")
		tr.ProcessRequestHeader(header)
		res := v.Fetch(tr)
		if !utils.SameStringSlice(res, []string{"def", "jkl"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
