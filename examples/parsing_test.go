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
	// Output:
	// ([]parser.Directive) (len=5 cap=8) {
	//  (*parser.TriBoolArgDirective)({
	//   Tk: (int) 129,
	//   Value: (int) 2
	//  }),
	//  (*parser.BoolArgDirective)({
	//   Tk: (int) 130,
	//   Value: (bool) true
	//  }),
	//  (*parser.BoolArgDirective)({
	//   Tk: (int) 131,
	//   Value: (bool) false
	//  }),
	//  (*parser.RuleDirective)({
	//   Variable: ([]*parser.Variable) (len=6 cap=8) {
	//    (*parser.Variable)({
	//     Tk: (int) 141,
	//     Index: (string) "",
	//     Count: (bool) false,
	//     Exclusion: (bool) false
	//    }),
	//    (*parser.Variable)({
	//     Tk: (int) 141,
	//     Index: (string) (len=7) "/__utm/",
	//     Count: (bool) false,
	//     Exclusion: (bool) true
	//    }),
	//    (*parser.Variable)({
	//     Tk: (int) 142,
	//     Index: (string) "",
	//     Count: (bool) false,
	//     Exclusion: (bool) false
	//    }),
	//    (*parser.Variable)({
	//     Tk: (int) 136,
	//     Index: (string) "",
	//     Count: (bool) false,
	//     Exclusion: (bool) false
	//    }),
	//    (*parser.Variable)({
	//     Tk: (int) 135,
	//     Index: (string) "",
	//     Count: (bool) false,
	//     Exclusion: (bool) false
	//    }),
	//    (*parser.Variable)({
	//     Tk: (int) 156,
	//     Index: (string) (len=2) "/*",
	//     Count: (bool) false,
	//     Exclusion: (bool) false
	//    })
	//   },
	//   Operator: (*parser.Operator)({
	//    Tk: (int) 157,
	//    Not: (bool) false,
	//    Argument: (string) (len=40) "(?i:sleep(s*?d*?s*?)|benchmark(.*?,.*?))"
	//   }),
	//   Actions: (*parser.Actions)({
	//    Id: (int) 942160,
	//    Phase: (int) 2,
	//    Trans: ([]*parser.Trans) (len=2 cap=2) {
	//     (*parser.Trans)({
	//      Tk: (int) 186
	//     }),
	//     (*parser.Trans)({
	//      Tk: (int) 185
	//     })
	//    },
	//    Action: ([]*parser.Action) (len=13 cap=16) {
	//     (*parser.Action)({
	//      Tk: (int) 171,
	//      Argument: (string) ""
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 181,
	//      Argument: (string) ""
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 164,
	//      Argument: (string) (len=54) "Detects blind sqli tests using sleep() or benchmark()."
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 179,
	//      Argument: (string) (len=72) "'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 166,
	//      Argument: (string) (len=17) "application-multi"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 166,
	//      Argument: (string) (len=14) "language-multi"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 166,
	//      Argument: (string) (len=14) "platform-multi"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 166,
	//      Argument: (string) (len=11) "attack-sqli"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 166,
	//      Argument: (string) (len=34) "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 178,
	//      Argument: (string) (len=17) "'OWASP_CRS/3.1.0'"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 168,
	//      Argument: (string) (len=1) "2"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 180,
	//      Argument: (string) (len=54) "'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 180,
	//      Argument: (string) (len=52) "'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
	//     })
	//    }
	//   })
	//  }),
	//  (*parser.RuleDirective)({
	//   Variable: ([]*parser.Variable) (len=1 cap=1) {
	//    (*parser.Variable)({
	//     Tk: (int) 144,
	//     Index: (string) (len=10) "User-Agent",
	//     Count: (bool) false,
	//     Exclusion: (bool) false
	//    })
	//   },
	//   Operator: (*parser.Operator)({
	//    Tk: (int) 157,
	//    Not: (bool) false,
	//    Argument: (string) (len=2) "^$"
	//   }),
	//   Actions: (*parser.Actions)({
	//    Id: (int) 920330,
	//    Phase: (int) 2,
	//    Trans: ([]*parser.Trans) (len=1 cap=1) {
	//     (*parser.Trans)({
	//      Tk: (int) 186
	//     })
	//    },
	//    Action: ([]*parser.Action) (len=10 cap=16) {
	//     (*parser.Action)({
	//      Tk: (int) 182,
	//      Argument: (string) ""
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 164,
	//      Argument: (string) (len=23) "Empty User Agent Header"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 166,
	//      Argument: (string) (len=17) "application-multi"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 166,
	//      Argument: (string) (len=14) "language-multi"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 166,
	//      Argument: (string) (len=14) "platform-multi"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 166,
	//      Argument: (string) (len=15) "attack-protocol"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 166,
	//      Argument: (string) (len=44) "OWASP_CRS/PROTOCOL_VIOLATION/EMPTY_HEADER_UA"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 178,
	//      Argument: (string) (len=17) "'OWASP_CRS/3.1.0'"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 168,
	//      Argument: (string) (len=1) "5"
	//     }),
	//     (*parser.Action)({
	//      Tk: (int) 180,
	//      Argument: (string) (len=50) "'tx.anomaly_score_pl1=+%{tx.notice_anomaly_score}'"
	//     })
	//    }
	//   })
	//  })
	// }
}
