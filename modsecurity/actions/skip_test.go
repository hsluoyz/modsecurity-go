package actions

import (
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func TestSkip(t *testing.T) {
	engine := modsecurity.NewEngine()
	ruleSet := modsecurity.NewSecRuleSet()
	t.Run("skip", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, ruleSet)
		if err != nil {
			t.Error(err)
			return
		}
		skip := NewActionSkip()
		skip.Do(tr)
		i := tr.NextRule()
		if i != modsecurity.StatusEndOfRules {
			t.Errorf("without arg expect jump to end of rule but got %d", i)
		}
	})
}
