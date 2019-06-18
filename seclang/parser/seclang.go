package parser

func init() {
	initDirectives()
}

func initDirectives() {
	RegisterDir(TkDirRule, `SecRule`, RuleDirectiveScaner)
	RegisterDir(TkDirRuleEng, `SecRuleEngine`, TriBoolArgDirectiveFactory(TkDirRuleEng))
	RegisterDir(TkDirReqBody, `SecRequestBodyAccess`, BoolArgDirectiveFactory(TkDirReqBody))
	RegisterDir(TkDirResBody, `SecResponseBodyAccess`, BoolArgDirectiveFactory(TkDirResBody))
}
