# This Project Is WIP.

This Project is work in progress. Api will be changed frequently. Not recommended for production use.

# ModSecurity-Go

[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/senghoo/modsecurity-go)
[![CI Status](https://travis-ci.org/senghoo/modsecurity-go.svg?branch=master)](https://travis-ci.org/senghoo/modsecurity-go)
[![Coverage Status](https://coveralls.io/repos/github/senghoo/modsecurity-go/badge.svg?branch=master)](https://coveralls.io/github/senghoo/modsecurity-go?branch=master)
[![codebeat badge](https://codebeat.co/badges/e6d5534b-34a4-4420-a319-e3f7245cdc0e)](https://codebeat.co/projects/github-com-senghoo-modsecurity-go-master)
[![License](https://img.shields.io/github/license/senghoo/modsecurity-go.svg)](https://github.com/senghoo/modsecurity-go/blob/master/LICENSE)

ModSecurity-Go is golang port for [ModSecurity](https://github.com/SpiderLabs/ModSecurity).

Project is Working in progress.

The current goal is to implement [ModSecurity Rules Language Porting Specification](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Rules-Language-Porting-Specification) [Level 1](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Rules-Language-Porting-Specification#level-1-core-features)

TODO:

- [x] SecLang parser
- [ ] Implement SecLang Processor (WIP)
- [ ] Implement SecLang [Level 1](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Rules-Language-Porting-Specification#level-1-core-features)
- [ ] Compatible with [OWASP](https://github.com/SpiderLabs/owasp-modsecurity-crs)


# Usage 

## Build Rules with Go

For full example see [Rules with Go Example](https://github.com/senghoo/modsecurity-go/blob/master/examples/rule_from_go_test.go)

```
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
	rule.AppendVariables(modsecurity.NewVariableRequestURI())
	// Operation: rx select
	op, err := modsecurity.NewOperatorRx("select")
	if err != nil {
		panic(err)
	}
	rule.SetOperator(op)
	// Action: deny
	rule.AppendActions(modsecurity.NewActionDeny())
	ruleSet.AddRules(rule)

	// running rule
	// make Transaction
	ts := modsecurity.NewTransaction(e, ruleSet)

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
	//   (string) (len=73) "[client 127.0.0.1:12345](phase 2)ModSecurity: Access denied with code 403"
	//  },
	//  Disruptive: (bool) true
	// })
```

## Seclang Parsing

For full example see [Parser Example](https://github.com/senghoo/modsecurity-go/blob/master/examples/parsing_test.go)

```

import "github.com/senghoo/modsecurity-go/libmodsecurity/seclang"

var rules = `<<<some modsecurity rules>>`
scaner := seclang.NewSecLangScannerFromString(rules)
d, err := scaner.AllDirective()
if err != nil {
	panic(err)
}
fmt.Printf("%#v\n", d)
    
```

# Supported Features

## Directives

* SecRuleEngine
* SecRule
* SecRequestBodyAccess
* SecResponseBodyAccess

## Variables

* ARGS
* ARGS_NAMES
* QUERY_STRING
* REMOTE_ADDR
* REQUEST_BASENAME
* REQUEST_BODY
* REQUEST_COOKIES
* REQUEST_COOKIES_NAMES
* REQUEST_FILENAME
* REQUEST_HEADERS
* REQUEST_HEADERS_NAMES
* REQUEST_METHOD
* REQUEST_PROTOCOL
* REQUEST_URI
* RESPONSE_BODY
* RESPONSE_CONTENT_LENGTH
* RESPONSE_CONTENT_TYPE
* RESPONSE_HEADERS
* RESPONSE_HEADERS_NAMES
* RESPONSE_PROTOCOL
* RESPONSE_STATUS
* XML

## Operators

* rx
* eq
* ge
* gt
* le
* lt

## Actions

* allow
* msg
* id
* rev
* ver
* severity
* log
* deny
* block
* status
* phase
* t
* skip
* chain
* logdata
* setvar
* capture
* pass

## Transformation Functions

* lowercase
* urlDecode
* urlDecodeUni
* none
* compressWhitespace
* removeWhitespace
* replaceNulls
* removeNulls
