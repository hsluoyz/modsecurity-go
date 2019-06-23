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
		}
		variables, err := MakeVariables(vs)
		if err != nil {
			t.Error(err)
		}
		if len(variables) != 1 {
			t.Error("expect one variable")
		}
		if v, ok := variables[0].(*modsecurity.VariableRequestURI); !ok {
			t.Errorf("except VariableRequestURI got %#v", v)
		}

	})

	t.Run("count REQUEST_URI", func(t *testing.T) {
		input := `&REQUEST_URI`
		scan := parser.NewSecLangScanner(strings.NewReader(input))
		vs, err := scan.ReadVariables()
		if err != nil {
			t.Error(err)
		}
		variables, err := MakeVariables(vs)
		if err != nil {
			t.Error(err)
		}
		if len(variables) != 1 {
			t.Error("expect one variable")
		}
		countV, ok := variables[0].(*modsecurity.CountVariable)
		if !ok {
			t.Errorf("except CountVariable got %#v", countV)
		}
		if v, ok := countV.Variable.(*modsecurity.VariableRequestURI); !ok {
			t.Errorf("except VariableRequestURI got %#v", v)
		}

	})
}
