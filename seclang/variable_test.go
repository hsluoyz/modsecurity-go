package seclang

import (
	"strings"
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
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
		variables, err := MakeVariables(vs)
		if err != nil {
			t.Error(err)
			return
		}
		if len(variables) != 1 {
			t.Error("expect one variable")
			return
		}
		if v, ok := variables[0].(*modsecurity.VariableRequestURI); !ok {
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
		variables, err := MakeVariables(vs)
		if err != nil {
			t.Error(err)
			return
		}
		if len(variables) != 1 {
			t.Error("expect one variable")
			return
		}
		countV, ok := variables[0].(*modsecurity.CountVariable)
		if !ok {
			t.Errorf("except CountVariable got %#v", countV)
			return
		}
		if v, ok := countV.Variable.(*modsecurity.VariableRequestURI); !ok {
			t.Errorf("except VariableRequestURI got %#v", v)
			return
		}

	})
}
