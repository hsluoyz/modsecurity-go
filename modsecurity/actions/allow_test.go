package actions

import (
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func TestAllow(t *testing.T) {
	engine := modsecurity.NewEngine()
	ruleSet := modsecurity.NewSecRuleSet()
	t.Run("without arg", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, ruleSet)
		if err != nil {
			t.Error(err)
			return
		}
		allow := NewActionAllow("")
		allow.Do(tr)
		i := tr.CurrentPhase()
		if i != modsecurity.PhaseLogging {
			t.Errorf("without arg expect jump to logging phase but got %d", i)
		}
	})
	t.Run("phase arg", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, ruleSet)
		if err != nil {
			t.Error(err)
			return
		}
		allow := NewActionAllow("phase")
		allow.Do(tr)
		i := tr.CurrentPhase()
		if i != modsecurity.PhaseConnection {
			t.Errorf("expect jump to connection phase but got %d", i)
		}
		allow.Do(tr)
		i = tr.CurrentPhase()
		if i != modsecurity.PhaseRequestHeaders {
			t.Errorf("expect jump to request headers phase but got %d", i)
		}
		allow.Do(tr)
		i = tr.CurrentPhase()
		if i != modsecurity.PhaseRequestBody {
			t.Errorf("expect jump to request body phase but got %d", i)
		}
		allow.Do(tr)
		i = tr.CurrentPhase()
		if i != modsecurity.PhaseResponseHeaders {
			t.Errorf("expect jump to response headers phase but got %d", i)
		}
		allow.Do(tr)
		i = tr.CurrentPhase()
		if i != modsecurity.PhaseResponseBody {
			t.Errorf("expect jump to response body phase but got %d", i)
		}
		allow.Do(tr)
		i = tr.CurrentPhase()
		if i != modsecurity.PhaseLogging {
			t.Errorf("expect jump to logging phase but got %d", i)
		}
		allow.Do(tr)
		i = tr.CurrentPhase()
		if i != modsecurity.PhaseEnd {
			t.Errorf("expect jump to end phase but got %d", i)
		}
		// one more tine to check dont out end
		allow.Do(tr)
		i = tr.CurrentPhase()
		if i != modsecurity.PhaseEnd {
			t.Errorf("expect jump to end phase but got %d", i)
		}
	})

	t.Run("request arg", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, ruleSet)
		if err != nil {
			t.Error(err)
			return
		}
		allow := NewActionAllow("request")
		allow.Do(tr)
		i := tr.CurrentPhase()
		if i != modsecurity.PhaseResponseHeaders {
			t.Errorf("expect jump to connection phase but got %d", i)
		}
	})
}
