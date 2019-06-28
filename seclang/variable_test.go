package seclang

import (
	"net/url"
	"strings"
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/modsecurity/variables"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

func TestMakeVariables(t *testing.T) {
	t.Run("REQUEST_URI", func(t *testing.T) {
		input := `REQUEST_URI`
		scan := parser.NewSecLangScanner(strings.NewReader(input))
		vs, err := scan.ReadVariables()
		if err != nil {
			t.Error(err)
			return
		}
		vars, err := MakeVariables(vs)
		if err != nil {
			t.Error(err)
			return
		}
		if len(vars) != 1 {
			t.Error("expect one variable")
			return
		}
		if v, ok := vars[0].(*variables.VariableRequestURI); !ok {
			t.Errorf("except VariableRequestURI got %#v", v)
			return
		}

	})

	t.Run("count REQUEST_URI", func(t *testing.T) {
		input := `&REQUEST_URI`
		scan := parser.NewSecLangScanner(strings.NewReader(input))
		vs, err := scan.ReadVariables()
		if err != nil {
			t.Error(err)
			return
		}
		vars, err := MakeVariables(vs)
		if err != nil {
			t.Error(err)
			return
		}
		if len(vars) != 1 {
			t.Error("expect one variable")
			return
		}
		countV, ok := vars[0].(*variables.CountVariable)
		if !ok {
			t.Errorf("except CountVariable got %#v", countV)
			return
		}
		if v, ok := countV.Variable.(*variables.VariableRequestURI); !ok {
			t.Errorf("except VariableRequestURI got %#v", v)
			return
		}

	})
	t.Run("ARGS_GET:a1", func(t *testing.T) {
		rules := `
SecRuleEngine On
SecRule ARGS_GET \
        '@rx v1' \
        "id:123,\
        phase:2,\
        t:lowercase,\
        deny"
SecRule ARGS_GET:a2 \
        '@rx v2' \
        "id:123,\
        phase:2,\
        t:lowercase,\
        deny"
SecRule ARGS_GET:/^b/ \
        '@rx v3' \
        "id:123,\
        phase:2,\
        t:lowercase,\
        deny"
`
		eng := modsecurity.NewEngine()
		rs, err := NewDireSetFromSecLangString(rules)
		if err != nil {
			t.Error(err)
			return
		}
		err = rs.Execute(eng)
		if err != nil {
			t.Error(err)
			return
		}
		testDatas := map[string]int{
			"/?query=v1": 403,
			"/?query=v3": 200,
			"/?a2=v2":    403,
			"/?a2=ok":    200,
			"/?a1=v2":    200,
			"/?b1=v3":    403,
			"/?b2=ok":    200,
			"/?a1=v3":    200,
		}
		for data, status := range testDatas {
			ts, err := eng.NewTransaction()
			if err != nil {
				t.Error(err)
				return
			}
			ts.ProcessConnection("127.0.0.1", "12345", "127.0.0.1", "80")
			u, err := url.Parse(data)
			if err != nil {
				t.Error(err)
				return
			}
			ts.ProcessRequestURL(u, "GET", "HTTP/1.1")
			ts.ProcessRequestHeader(nil)
			i := ts.Result()
			if i.Status != status {
				t.Errorf("url %s expect get %d but got %d, result %#v", data, status, i.Status, i)
			}
		}
	})

}
