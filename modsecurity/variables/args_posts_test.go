package variables

import (
	"net/url"
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/utils"
)

func TestVariableArgsPost(t *testing.T) {
	v := NewVariableArgsPost()
	if v.Name() != "ARGS_POST" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	engine := modsecurity.NewEngine()
	engine.RequestBodyAccess = true
	t.Run("urlencoded", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		u, _ := url.Parse("http://localhost/query?a1=1&a2=2&b1=3&b2=4")
		header := map[string][]string{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}
		body := `a1=1&a2=2&b1=3&b2=4`
		tr.ProcessRequestURL(u, "POST", "HTTP/1.1")
		tr.ProcessRequestHeader(header)
		tr.AppendRequestBody([]byte(body))
		res := v.Fetch(tr)
		if !utils.SameStringSlice(res, []string{"1", "2", "3", "4"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
	t.Run("multipart", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		u, _ := url.Parse("http://localhost/query")
		header := map[string][]string{
			"Content-Type": {"MultIpart/mixed; boundary=foo"},
		}
		body := "--foo\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\nA section\r\n" +
			"--foo\r\nContent-Disposition: form-data; name=\"test2\"\r\n\r\nAnother section\r\n" +
			"--foo--\r\n"
		tr.ProcessRequestURL(u, "POST", "HTTP/1.1")
		tr.ProcessRequestHeader(header)
		tr.AppendRequestBody([]byte(body))
		res := v.Fetch(tr)
		if !utils.SameStringSlice(res, []string{"A section", "Another section"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
