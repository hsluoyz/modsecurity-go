package parser

// some rules from OWASP
var testRules1 = `
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
var testRules1Expect = []Directive{
	&TriBoolArgDirective{
		Tk:    TkDirRuleEng,
		Value: TriBoolElse,
	},
	&BoolArgDirective{
		Tk:    TkDirReqBody,
		Value: true,
	},
	&BoolArgDirective{
		Tk:    TkDirResBody,
		Value: false,
	},
	&RuleDirective{
		Variable: []*Variable{
			&Variable{Tk: TkVarRequestCookies},
			&Variable{Tk: TkVarRequestCookies, Index: "/__utm/", Exclusion: true},
			&Variable{Tk: TkVarRequestCookiesNames},
			&Variable{Tk: TkVarArgsNames},
			&Variable{Tk: TkVarArgs},
			&Variable{Tk: TkVarXML, Index: "/*"},
		},
		Operator: &Operator{
			Tk:       TkOpRx,
			Argument: "(?i:sleep(s*?d*?s*?)|benchmark(.*?,.*?))",
		},
		Actions: &Actions{
			Id:    942160,
			Phase: 2,
			Trans: []*Trans{
				&Trans{Tk: TkTransNone},
				&Trans{Tk: TkTransUrlDecodeUni},
			},
			Action: []*Action{
				&Action{Tk: TkActionBlock},
				&Action{Tk: TkActionCapture},
				&Action{Tk: TkActionMsg, Argument: "Detects blind sqli tests using sleep() or benchmark()."},
				&Action{Tk: TkActionLogData, Argument: "'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'"},
				&Action{Tk: TkActionTag, Argument: "application-multi"},
				&Action{Tk: TkActionTag, Argument: "language-multi"},
				&Action{Tk: TkActionTag, Argument: "platform-multi"},
				&Action{Tk: TkActionTag, Argument: "attack-sqli"},
				&Action{Tk: TkActionTag, Argument: "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"},
				&Action{Tk: TkActionVer, Argument: "'OWASP_CRS/3.1.0'"},
				&Action{Tk: TkActionSeverity, Argument: "2"},
				&Action{Tk: TkActionSetVar, Argument: "'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"},
				&Action{Tk: TkActionSetVar, Argument: "'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"},
			},
		},
	},
	&RuleDirective{
		Variable: []*Variable{
			&Variable{
				Tk:    TkVarRequestHeaders,
				Index: "User-Agent",
			},
		},
		Operator: &Operator{
			Tk:       TkOpRx,
			Argument: "^$",
		},
		Actions: &Actions{
			Id:    920330,
			Phase: 2,
			Trans: []*Trans{
				&Trans{Tk: TkTransNone},
			},
			Action: []*Action{
				&Action{Tk: TkActionPass},
				&Action{Tk: TkActionMsg, Argument: "Empty User Agent Header"},
				&Action{Tk: TkActionTag, Argument: "application-multi"},
				&Action{Tk: TkActionTag, Argument: "language-multi"},
				&Action{Tk: TkActionTag, Argument: "platform-multi"},
				&Action{Tk: TkActionTag, Argument: "attack-protocol"},
				&Action{Tk: TkActionTag, Argument: "OWASP_CRS/PROTOCOL_VIOLATION/EMPTY_HEADER_UA"},
				&Action{Tk: TkActionVer, Argument: "'OWASP_CRS/3.1.0'"},
				&Action{Tk: TkActionSeverity, Argument: "5"},
				&Action{Tk: TkActionSetVar, Argument: "'tx.anomaly_score_pl1=+%{tx.notice_anomaly_score}'"},
			},
		},
	},
}
