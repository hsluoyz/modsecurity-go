package seclang

import (
	"fmt"
	"net/url"
	"reflect"
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/utils"
)

func TestRuleSet(t *testing.T) {
	rule := `SecRuleEngine On
                 SecRule REQUEST_URI '@rx cmd' \
                            "id:123,\
                             phase:2,\
                             t:lowercase,\
                             deny"
`
	eng := modsecurity.NewEngine()
	rs, err := NewDireSetFromSecLangString(rule)
	if err != nil {
		t.Error(err)
		return
	}
	err = rs.Execute(eng)
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("deny", func(t *testing.T) {
		ts, err := eng.NewTransaction()
		if err != nil {
			t.Error(err)
			return
		}
		ts.ProcessConnection("127.0.0.1", "12345", "127.0.0.1", "80")
		u, err := url.Parse(`/search?="a';CMD echo '1"`)
		if err != nil {
			t.Error(err)
			return
		}
		ts.ProcessRequestURL(u, "GET", "HTTP/1.1")
		ts.ProcessRequestHeader(nil)
		i := ts.Result()
		expect := &modsecurity.Intervention{
			Status: 403,
			Log: []string{
				"[client 127.0.0.1:12345] (phase 2) ModSecurity: Access denied with code 403",
			},
			Disruptive: true,
		}
		if !reflect.DeepEqual(i, expect) {
			fmt.Println("====expect====")
			utils.Pprint(expect)
			fmt.Println("====got====")
			utils.Pprint(i)
			t.Error("unmatch")
		}
	})

	t.Run("allow", func(t *testing.T) {
		ts, err := eng.NewTransaction()
		if err != nil {
			t.Error(err)
			return
		}
		ts.ProcessConnection("127.0.0.1", "12345", "127.0.0.1", "80")
		u, err := url.Parse(`/search?="a1"`)
		if err != nil {
			t.Error(err)
			return
		}
		ts.ProcessRequestURL(u, "GET", "HTTP/1.1")
		ts.ProcessRequestHeader(nil)
		i := ts.Result()
		expect := &modsecurity.Intervention{
			Status: 200,
		}
		if !reflect.DeepEqual(i, expect) {
			fmt.Println("====expect====")
			utils.Pprint(expect)
			fmt.Println("====got====")
			utils.Pprint(i)
			t.Error("unmatch")
		}
	})
}

func TestRuleSetChain(t *testing.T) {
	rule := `
SecRule REQUEST_URI '@rx cmd' \
    "id:123,\
    phase:2,\
    t:lowercase,\
    chain,\
    deny"
    SecRule ARGS_POST '@rx abc' log,chain
        SecRule ARGS_GET '@rx xyz' status:403
`
	rs, err := NewDireSetFromSecLangString(rule)
	if err != nil {
		t.Error(err)
		return
	}
	if len(rs.dires) != 1 {
		t.Errorf("expect one dire but got %d", len(rs.dires))
		return
	}
	dr, ok := rs.dires[0].(*DireRule)
	if !ok {
		t.Errorf("expect DireRule but got %#v", rs.dires[0])
		return
	}
	if len(dr.rule.SubRules) != 2 {
		t.Errorf("expect 2 subdire but got %d", len(dr.rule.SubRules))
		return
	}
}
