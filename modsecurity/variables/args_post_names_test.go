package variables

import (
	"net/url"
	"strings"
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/utils"
)

func TestVariableArgsPostNames(t *testing.T) {
	v := NewVariableArgsPostNames()
	if v.Name() != "ARGS_POST_NAMES" {
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
		u, _ := url.Parse("http://localhost/query")
		header := map[string][]string{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}
		body := `a1=1&a2=2&b1=3&b2=4`
		tr.ProcessRequestURL(u, "POST", "HTTP/1.1")
		tr.ProcessRequestHeader(header)
		tr.AppendRequestBody([]byte(body))
		res := v.Fetch(tr)
		if !utils.SameStringSlice(res, []string{"a1", "a2", "b1", "b2"}) {
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
		if !utils.SameStringSlice(res, []string{"text", "test2"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
	t.Run("urlencoded error", func(t *testing.T) {
		engine.Limits.RequestBodyInMem = 64
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		u, _ := url.Parse("http://localhost/query?a1=1&a2=2&b1=3&b2=4")
		header := map[string][]string{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}
		// out of memory limit
		body := strings.Repeat(`a1=1&a2=2&b1=3&b2=4&`, 20)
		tr.ProcessRequestURL(u, "POST", "HTTP/1.1")
		tr.ProcessRequestHeader(header)
		tr.AppendRequestBody([]byte(body))
		res := v.Fetch(tr)
		if res != nil {
			t.Errorf("expect nil got %q", res)
		}
		if tr.Errors.RequestBodyError == nil {
			t.Error("expect body error")
		}
		if !tr.Abort {
			t.Error("expect abort")
		}
	})
}
