# This Source is WIP. not working yet now !!

# ModSecurity-Go
ModSecurity-Go is golang port for [ModSecurity](https://github.com/SpiderLabs/ModSecurity).

Project is Working in progress.

The current goal is to implement [ModSecurity Rules Language Porting Specification](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Rules-Language-Porting-Specification) [Level 1](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Rules-Language-Porting-Specification#level-1-core-features)

TODO:

- [x] SecLang parser
- [ ] Implement SecLang Processor (WIP)
- [ ] Implement SecLang [Level 1](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Rules-Language-Porting-Specification#level-1-core-features)
- [ ] Compatible with [OWASP](https://github.com/SpiderLabs/owasp-modsecurity-crs)


# Usage 

## Seclang Parsing

For full example see [Parser Example](https://github.com/senghoo/modsecurity-go/blob/master/examples/parsing.go)

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
