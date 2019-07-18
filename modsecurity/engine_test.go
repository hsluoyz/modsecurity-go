package modsecurity

import (
	"testing"

	"github.com/senghoo/modsecurity-go/utils"
)

type variableConst struct {
	vars []string
}

func (*variableConst) Name() string {
	return "CONST"
}
func (*variableConst) Include(string) error { return nil }
func (*variableConst) Exclude(string) error { return nil }
func (v *variableConst) Fetch(t *Transaction) []string {
	return v.vars
}

type transAppendString struct {
	val string
}

func (*transAppendString) Name() string {
	return "APPEND_STRING"
}
func (t *transAppendString) Trans(tr *Transaction, s string) string {
	return s + t.val
}

type operatorEq struct {
	val string
}

func (o *operatorEq) Name() string {
	return "eq"
}
func (o *operatorEq) Args() string {
	return o.val
}

func (o *operatorEq) Match(tr *Transaction, s string) bool {
	return o.val == s
}

type actionLog struct {
	log string
}

func (*actionLog) Name() string {
	return "deny"
}
func (*actionLog) ActionGroup() int {
	return ActionGroupNonDisruptive
}

func (a *actionLog) Value() string {
	return a.log
}

func (a *actionLog) Do(t *Transaction) {
	t.Logf(a.log)
}

func TestEngine(t *testing.T) {
	rule := &SecRule{
		Id: 1,
	}
	rule.AppendVariables(&variableConst{[]string{"abc"}})
	rule.AppendTrans(&transAppendString{"def"})
	rule.SetOperator(&operatorEq{"abcdef"})
	rule.AppendActions(&actionLog{"ok"})

	// request phase
	e := NewEngine()
	rule.Phase = PhaseConnection
	ruleSet := NewSecRuleSet()
	ruleSet.AddRules(rule)
	tr, err := NewTransaction(e, ruleSet)
	if err != nil {
		t.Error(err)
		return
	}
	tr.ProcessConnection("192.168.1.1", "1234", "", "")
	if !utils.SameStringSlice(tr.Intervention().Log, []string{"[client 192.168.1.1:1234] (phase 1) ok"}) {
		t.Errorf("expect ok log, got %q", tr.Intervention().Log)
	}

	// request phase
	e = NewEngine()
	rule.Phase = PhaseRequestHeaders
	ruleSet = NewSecRuleSet()
	ruleSet.AddRules(rule)
	tr, err = NewTransaction(e, ruleSet)
	if err != nil {
		t.Error(err)
		return
	}
	tr.ProcessRequestHeader(nil)
	if !utils.SameStringSlice(tr.Intervention().Log, []string{"[client :] (phase 2) ok"}) {
		t.Errorf("expect ok log, got %q", tr.Intervention().Log)
	}

	// request body phase
	e = NewEngine()
	rule.Phase = PhaseRequestBody
	ruleSet = NewSecRuleSet()
	ruleSet.AddRules(rule)
	tr, err = NewTransaction(e, ruleSet)
	if err != nil {
		t.Error(err)
		return
	}
	tr.ProcessRequestBody()
	if !utils.SameStringSlice(tr.Intervention().Log, []string{"[client :] (phase 3) ok"}) {
		t.Errorf("expect ok log, got %q", tr.Intervention().Log)
	}

	// response header phase
	e = NewEngine()
	rule.Phase = PhaseResponseHeaders
	ruleSet = NewSecRuleSet()
	ruleSet.AddRules(rule)
	tr, err = NewTransaction(e, ruleSet)
	if err != nil {
		t.Error(err)
		return
	}
	tr.ProcessResponseHeaders(200, "HTTP/1.1", nil)
	if !utils.SameStringSlice(tr.Intervention().Log, []string{"[client :] (phase 4) ok"}) {
		t.Errorf("expect ok log, got %q", tr.Intervention().Log)
	}

	// response body phase
	e = NewEngine()
	rule.Phase = PhaseResponseBody
	e.AddSecRule(rule)
	tr, err = e.NewTransaction()
	if err != nil {
		t.Error(err)
		return
	}
	tr.ProcessResponseBody()
	if !utils.SameStringSlice(tr.Intervention().Log, []string{"[client :] (phase 5) ok"}) {
		t.Errorf("expect ok log, got %q", tr.Intervention().Log)
	}

	// response logging phase
	e = NewEngine()
	rule.Phase = PhaseLogging
	e.AddSecRule(rule)
	tr, err = e.NewTransaction()
	if err != nil {
		t.Error(err)
		return
	}
	tr.ProcessLogging()
	if !utils.SameStringSlice(tr.Intervention().Log, []string{"[client :] (phase 6) ok"}) {
		t.Errorf("expect ok log, got %q", tr.Intervention().Log)
	}
}

func TestEngine_Enable(t *testing.T) {
	e := NewEngine()
	e.Enable(StatusOn)
	if !(e.Enabled && !e.DetectionOnly) {
		t.Errorf("unexpected status %#v", e)
	}
	e.Enable(StatusOff)
	if !(!e.Enabled && !e.DetectionOnly) {
		t.Errorf("unexpected status %#v", e)
	}
	e.Enable(StatusDect)
	if !(!e.Enabled && e.DetectionOnly) {
		t.Errorf("unexpected status %#v", e)
	}
}
