package main

import (
	"net/url"

	"github.com/davecgh/go-spew/spew"
	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/modsecurity/actions"
	"github.com/hsluoyz/modsecurity-go/modsecurity/operators"
	"github.com/hsluoyz/modsecurity-go/modsecurity/variables"
)

func ExampleRuleFromGo() {
	// make engine
	e := modsecurity.NewEngine()
	// enable engine
	e.Enable(modsecurity.StatusOn)
	// make rule set
	ruleSet := modsecurity.NewSecRuleSet()
	// make rule
	rule := &modsecurity.SecRule{
		Phase: modsecurity.PhaseRequestHeaders,
	}
	// Variable: REQUEST_URI
	rule.AppendVariables(variables.NewVariableRequestURI())
	// Operation: rx select
	op, err := operators.NewOperatorRx("select")
	if err != nil {
		panic(err)
	}
	rule.SetOperator(op)
	// Action: deny
	rule.AppendActions(actions.NewActionDeny())
	ruleSet.AddRules(rule)

	// running rule
	// make Transaction
	ts, err := modsecurity.NewTransaction(e, ruleSet)
	if err != nil {
		panic(err)
	}

	// request header phase
	ts.ProcessConnection("127.0.0.1", "12345", "127.0.0.1", "80")

	u, err := url.Parse(`/search?="a';select '1"`)
	if err != nil {
		panic(err)
	}

	ts.ProcessRequestURL(u, "GET", "HTTP/1.1")
	ts.ProcessRequestHeader(nil)
	i := ts.Result()
	pprint := spew.NewDefaultConfig()
	pprint.DisablePointerAddresses = true
	pprint.Dump(i)
	// Output:
	// (*modsecurity.Intervention)({
	//  Status: (int) 403,
	//  Pause: (time.Duration) 0s,
	//  Url: (*url.URL)(<nil>),
	//  Log: ([]string) (len=1 cap=1) {
	//   (string) (len=75) "[client 127.0.0.1:12345] (phase 2) ModSecurity: Access denied with code 403"
	//  },
	//  Disruptive: (bool) true
	// })
}
