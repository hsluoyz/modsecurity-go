package seclang

func init() {
	initDirectives()
}

func initDirectives() {
	registerDir(TkDirRule, `SecRule`, RuleDirectiveScaner)
	registerDir(TkDirRuleEng, `SecRuleEngine`, TriBoolArgDirectiveFactory(TkDirRuleEng))
	registerDir(TkDirReqBody, `SecRequestBodyAccess`, BoolArgDirectiveFactory(TkDirReqBody))
	registerDir(TkDirResBody, `SecResponseBodyAccess`, BoolArgDirectiveFactory(TkDirResBody))
}
