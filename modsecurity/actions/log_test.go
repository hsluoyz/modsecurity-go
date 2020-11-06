package actions

import (
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func TestLog(t *testing.T) {
	engine := modsecurity.NewEngine()
	ruleSet := modsecurity.NewSecRuleSet()
	tr, err := modsecurity.NewTransaction(engine, ruleSet)
	if err != nil {
		t.Error(err)
		return
	}
	log := NewActionLog()
	log.Do(tr)
	i := tr.Intervention()
	if len(i.Log) != 1 {
		t.Errorf("expect one log but got %d", len(i.Log))
	}
}
