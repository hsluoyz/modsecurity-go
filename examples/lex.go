package main

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/libmodsecurity/seclang"
)

func main() {

	lex := seclang.NewSecLangLex()
	rules := `SecComponentSignature "core ruleset/2.1.3"`
	scan, err := lex.Scanner([]byte(rules))
	if err != nil {
		panic(err)
	}
	for {
		tok, err, eos := scan.Next()
		if err != nil {
			panic(err)
		}
		if eos {
			break
		}
		fmt.Printf("Got token %#v", tok)
	}
}
