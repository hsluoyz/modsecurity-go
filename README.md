# This Source is WIP. not working yet now !!

# ModSecurity-Go
ModSecurity-Go is golang port for [ModSecurity](https://github.com/SpiderLabs/ModSecurity).

Project is Working in progress.

The current goal is to implement [ModSecurity Rules Language Porting Specification](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Rules-Language-Porting-Specification) [Level 1](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Rules-Language-Porting-Specification#level-1-core-features)

TODO:

- [ ] SecLang Lexer (WIP)
- [ ] SecLang parser
- [ ] Implement SecLang [Level 1](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Rules-Language-Porting-Specification#level-1-core-features)
- [ ] Compatible with [OWASP](https://github.com/SpiderLabs/owasp-modsecurity-crs)


# Usage 

## Lexer(WIP)

```

	lex := seclang.NewSecLangLex()
    rules := "<<modsecurity rules>>"
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
```
