package main

import (
	"github.com/senghoo/modsecurity-go/seclang/parser"
	"github.com/senghoo/modsecurity-go/utils"
)

var rules = `
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i:sleep\(\s*?\d*?\s*?\)|benchmark\(.*?\,.*?\))" \
    "id:942160,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects blind sqli tests using sleep() or benchmark().',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    ver:'OWASP_CRS/3.1.0',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecRule REQUEST_HEADERS:User-Agent "@rx ^$" \
    "id:920330,\
    phase:2,\
    pass,\
    t:none,\
    msg:'Empty User Agent Header',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'OWASP_CRS/PROTOCOL_VIOLATION/EMPTY_HEADER_UA',\
    ver:'OWASP_CRS/3.1.0',\
    severity:'NOTICE',\
    setvar:'tx.anomaly_score_pl1=+%{tx.notice_anomaly_score}'"
`

func ExampleParser() {
	scaner := parser.NewSecLangScannerFromString(rules)
	d, err := scaner.AllDirective()
	if err != nil {
		panic(err)
	}
	utils.Pprint(d)
}
