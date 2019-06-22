package modsecurity

import (
	"fmt"
	"net/url"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
)

func TestEngine(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	t.Run("url rx match deny", func(t *testing.T) {
		e := NewEngine()
		e.Enable(StatusOn)
		ruleSet := NewSecRuleSet()
		rule := &SecRule{
			Phase: PhaseRequestHeaders,
		}
		rule.AppendVariables(NewVariableRequestURI())
		op, err := NewOperatorRx("select")
		if err != nil {
			t.Error(err)
			return
		}
		rule.SetOperator(op)
		rule.AppendActions(NewActionDeny())
		ruleSet.AddRules(rule)
		ts := NewTransaction(e, ruleSet)
		ts.ProcessConnection("127.0.0.1", "12345", "127.0.0.1", "80")
		u, err := url.Parse(`/search?="a';select '1"`)
		if err != nil {
			t.Error(err)
			return
		}
		ts.ProcessRequestURL(u, "GET", "HTTP/1.1")
		ts.ProcessRequestHeader(nil)
		i := ts.Result()
		expect := &Intervention{
			Status: 403,
			Log: []string{
				"[client 127.0.0.1:12345](phase 2)ModSecurity: Access denied with code 403",
			},
			Disruptive: true,
		}
		if !reflect.DeepEqual(i, expect) {
			fmt.Println("====expect====")
			spew.Dump(expect)
			fmt.Println("====got====")
			spew.Dump(i)
			t.Error("unmatch")
		}
	})
}
