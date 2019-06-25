package modsecurity

import (
	"github.com/sirupsen/logrus"
)

const (
	PhaseBegin = iota
	PhaseConnection
	PhaseRequestHeaders
	PhaseRequestBody
	PhaseResponseHeaders
	PhaseResponseBody
	PhaseLogging
	PhaseEnd
)

type SecRule struct {
	Id        int
	Phase     int
	Variables []Variable
	Trans     []Trans
	Operator  Operator
	Actions   []Action
	Not       bool
}

func (r *SecRule) AppendVariables(vs ...Variable) {
	r.Variables = append(r.Variables, vs...)
}
func (r *SecRule) AppendActions(vs ...Action) {
	r.Actions = append(r.Actions, vs...)
}
func (r *SecRule) AppendTrans(vs ...Trans) {
	r.Trans = append(r.Trans, vs...)
}
func (r *SecRule) SetOperator(o Operator) {
	r.Operator = o
}

func (r *SecRule) TransformString(s string) string {
	for _, t := range r.Trans {
		s = t.Trans(s)
	}
	return s
}

func (r *SecRule) TransformVariable(t *Transaction, variable Variable) []string {
	var res []string
	for _, v := range variable.Fetch(t) {
		res = append(res, r.TransformString(v))
	}
	return res
}

func (r *SecRule) FetchAllTransformedVariables(t *Transaction) []string {
	var res []string
	for _, v := range r.Variables {
		res = append(res, r.TransformVariable(t, v)...)
	}
	return res
}

func (r *SecRule) Match(t *Transaction) bool {
	for _, v := range r.FetchAllTransformedVariables(t) {
		if r.Not != r.Operator.Match(v) {
			return true
		}
	}
	return false
}

func (r *SecRule) Do(t *Transaction) {
	logrus.Debugf("running rule %#v", r)
	if !r.Match(t) {
		return
	}
	for _, action := range r.Actions {
		action.Do(t)
	}
}

func NewSecRuleSet() *SecRuleSet {
	return &SecRuleSet{
		Phases: make(map[int][]*SecRule),
	}
}

type SecRuleSet struct {
	Phases map[int][]*SecRule
}

func (rs *SecRuleSet) AddRules(rules ...*SecRule) {
	if rs.Phases == nil {
		rs.Phases = make(map[int][]*SecRule)
	}
	for _, rule := range rules {
		if rule.Phase >= PhaseEnd || rule.Phase <= PhaseBegin {
			continue
		}
		rs.Phases[rule.Phase] = append(rs.Phases[rule.Phase], rule)
	}
}

func (rs *SecRuleSet) ProcessPhase(t *Transaction, phase int) {
	if rs.Phases == nil {
		return
	}
	logrus.Debugf("running phase %d ", phase)
	for _, rule := range rs.Phases[phase] {
		rule.Do(t)
	}
}
