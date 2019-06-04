package seclang

import "github.com/timtadh/lexmachine/machines"

// NewSecLangLex generate new SecLang Lexer
func NewSecLangLex() *Lexer {
	lex := NewLexer()
	// skip space
	lex.Add(StateInit, []byte("( |\t|\n|\r)+"), func(scan *Scanner, match *machines.Match) (interface{}, error) {
		return nil, nil
	})
	LIQFreeTextArg(lex, StateInit, TkConfigComponentSig)
	LIQFreeTextArg(lex, StateInit, TkConfigSecServerSig)
	LIQFreeTextArg(lex, StateInit, TkConfigSecWebAppId)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecWebAppId)
	LI(lex, StateInit, TkConfigContentInjection)
	LIQNumberArg(lex, StateInit, TkConfigDirAuditDirMod)
	LINumberArg(lex, StateInit, TkConfigDirAuditDirMod)
	LIQPathArg(lex, StateInit, TkConfigDirAuditDir)
	LIPathArg(lex, StateInit, TkConfigDirAuditDir)
	LIQNewLineFreeTextArg(lex, StateInit, TkConfigSecArgumentSeparator)
	LINewLineFreeTextArg(lex, StateInit, TkConfigSecArgumentSeparator)
	LI(lex, StateInit, TkConfigDirAuditEng)
	LINumberArg(lex, StateInit, TkConfigDirAuditFleMod)
	LIPathArg(lex, StateInit, TkConfigDirAuditLog2)
	LIRegexArg(lex, StateInit, TkAuditParts, TkConfigDirAuditLogP)
	LIQRegexArg(lex, StateInit, TkAuditParts, TkConfigDirAuditLogP)
	LIPathArg(lex, StateInit, TkConfigDirAuditLog)
	LI(lex, StateInit, TkConfigDirAuditLogFmt)
	LI(lex, StateInit, TkJson)
	LI(lex, StateInit, TkNative)
	LIQPathArg(lex, StateInit, TkConfigDirAuditLog)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigDirAuditSts)
	LIQNewLineFreeTextArg(lex, StateInit, TkConfigDirAuditSts)
	LI(lex, StateInit, TkConfigDirAuditTpe)
	LIPathArg(lex, StateInit, TkConfigDirDebugLog)
	LIQPathArg(lex, StateInit, TkConfigDirDebugLog)
	LINumberArg(lex, StateInit, TkConfigDirDebugLvl)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigDirGeoDb)
	LINumberArg(lex, StateInit, TkConfigDirPcreMatchLimitRecursion)
	LINumberArg(lex, StateInit, TkConfigDirPcreMatchLimit)
	LINumberArg(lex, StateInit, TkConfigDirReqBodyInMemoryLimit)
	LI(lex, StateInit, TkConfigDirReqBodyLimitAction)
	LINumberArg(lex, StateInit, TkConfigDirReqBodyLimit)
	LINumberArg(lex, StateInit, TkConfigDirReqBodyNoFilesLimit)
	LI(lex, StateInit, TkConfigDirReqBody)
	LI(lex, StateInit, TkConfigDirResBodyLimitAction)
	LINumberArg(lex, StateInit, TkConfigDirResBodyLimit)
	LI(lex, StateInit, TkConfigDirResBody)
	LI(lex, StateInit, TkConfigDirRuleEng)
	LIQNewLineFreeTextArg(lex, StateInit, TkConfigDirSecMarker)
	LINewLineFreeTextArg(lex, StateInit, TkConfigDirSecMarker)
	LIFreeTextNewNumberLineArg(lex, StateInit, TkConfigDirUnicodeMapFile)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecRemoveRulesById)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecRemoveRulesByMsg)
	LIQFreeTextNewLineArg(lex, StateInit, TkConfigSecRemoveRulesByMsg)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecRemoveRulesByTag)
	LIQFreeTextNewLineArg(lex, StateInit, TkConfigSecRemoveRulesByTag)
	LI(lex, StateInit, TkConfigUpdloadKeepFiles)
	LI(lex, StateInit, TkConfigUpdloadSaveTmpFiles)
	LIPathArg(lex, StateInit, TkConfigUploadDir)
	LIQPathArg(lex, StateInit, TkConfigUploadDir)
	LINumberArg(lex, StateInit, TkConfigUploadFileLimit)
	LINumberArg(lex, StateInit, TkConfigUploadFileMode)
	LI(lex, StateInit, TkConfigValueAbort)
	LI(lex, StateInit, TkConfigValueDetc)
	LI(lex, StateInit, TkConfigValueHttps)
	LI(lex, StateInit, TkConfigValueOff)
	LI(lex, StateInit, TkConfigValueOn)
	LI(lex, StateInit, TkConfigValueParallel)
	LI(lex, StateInit, TkConfigValueProcessPartial)
	LI(lex, StateInit, TkConfigValueReject)
	LI(lex, StateInit, TkConfigValueRelevantOnly)
	LI(lex, StateInit, TkConfigValueSerial)
	LI(lex, StateInit, TkConfigValueWarn)
	LI(lex, StateInit, TkConfigXmlExternalEntity)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigDirResponseBodyMp)
	LI(lex, StateInit, TkConfigDirResponseBodyMpClear)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigDirSecArgSep)
	LINumberArg(lex, StateInit, TkConfigDirSecCookieFormat)
	LIQNewLineFreeTextArg(lex, StateInit, TkConfigSecCookiev0Separator)
	LINewLineFreeTextArg(lex, StateInit, TkConfigSecCookiev0Separator)
	LIPathArg(lex, StateInit, TkConfigDirSecDataDir)
	LIQPathArg(lex, StateInit, TkConfigDirSecDataDir)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigDirSecStatusEngine)
	LIPathArg(lex, StateInit, TkConfigDirSecTmpDir)
	LIQPathArg(lex, StateInit, TkConfigDirSecTmpDir)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecCacheTransformations)
	LIPathArg(lex, StateInit, TkConfigSecChrootDir)
	LIQPathArg(lex, StateInit, TkConfigSecChrootDir)
	LI(lex, StateInit, TkConfigConnEngine)
	LI(lex, StateInit, TkConfigSecHashEngine)
	LI(lex, StateInit, TkConfigSecHashKey)
	LI(lex, StateInit, TkConfigSecHashParam)
	LI(lex, StateInit, TkConfigSecHashMethodRx)
	LI(lex, StateInit, TkConfigSecHashMethodPm)
	LIPathArg(lex, StateInit, TkConfigDirGsbDb)
	LIQPathArg(lex, StateInit, TkConfigDirGsbDb)
	LI(lex, StateInit, TkConfigSecGuardianLog)
	LI(lex, StateInit, TkConfigSecInterceptOnError)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecConnRStateLimit)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecConnWStateLimit)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecSensorId)
	LI(lex, StateInit, TkConfigSecRuleInheritance)
	LINumberArg(lex, StateInit, TkConfigSecRulePerfTime)
	LI(lex, StateInit, TkConfigSecStreamInBodyInspection)
	LI(lex, StateInit, TkConfigSecStreamOutBodyInspection)
	LI(lex, StateInit, TkConfigSecDisableBackendCompress)
	LI(lex, StateInit, TkConfigSecRemoteRulesFailAction)
	LINumberArg(lex, StateInit, TkConfigSecCollectionTimeout)
	LIFreeTextNewLineArg(lex, StateInit, TkConfigSecHttpBlkey)
	LSkip(lex, StateInit, `[ \t]*[\n]`)
	LSkip(lex, StateInit, `#.*`)
	LSkip(lex, StateInit, `\r`)
	lex.AddString(StateInit, `["]`, TokenMaker(TkQuotationMark))
	lex.AddString(StateInit, `[,]`, TokenMaker(TkComma))
	// {CONFIG_SEC_UPDATE_TARGET_BY_TAG}[ \t]+["]{FREE_TEXT_NEW_LINE}["]         { state_variable_from = 1; BEGIN(TRANSACTION_TO_VARIABLE); return p::make_CONFIG_SEC_RULE_UPDATE_TARGET_BY_TAG(parserSanitizer(strchr(yytext, ' ') + 1), *driver.loc.back()); }
	// {CONFIG_SEC_UPDATE_TARGET_BY_TAG}[ \t]+{FREE_TEXT_SPACE_COMMA_QUOTE}      { state_variable_from = 1; BEGIN(TRANSACTION_TO_VARIABLE); return p::make_CONFIG_SEC_RULE_UPDATE_TARGET_BY_TAG(parserSanitizer(strchr(yytext, ' ') + 1), *driver.loc.back()); }
	// {CONFIG_SEC_UPDATE_TARGET_BY_MSG}[ \t]+["]{FREE_TEXT_NEW_LINE}["]         { state_variable_from = 1; BEGIN(TRANSACTION_TO_VARIABLE); return p::make_CONFIG_SEC_RULE_UPDATE_TARGET_BY_MSG(parserSanitizer(strchr(yytext, ' ') + 1), *driver.loc.back()); }
	// {CONFIG_SEC_UPDATE_TARGET_BY_MSG}[ \t]+{FREE_TEXT_SPACE_COMMA_QUOTE}      { state_variable_from = 1; BEGIN(TRANSACTION_TO_VARIABLE); return p::make_CONFIG_SEC_RULE_UPDATE_TARGET_BY_MSG(parserSanitizer(strchr(yytext, ' ') + 1), *driver.loc.back()); }
	// {CONFIG_SEC_UPDATE_TARGET_BY_ID}[ \t]+["]{FREE_TEXT_NEW_LINE}["]          { state_variable_from = 1; BEGIN(TRANSACTION_TO_VARIABLE); return p::make_CONFIG_SEC_RULE_UPDATE_TARGET_BY_ID(parserSanitizer(strchr(yytext, ' ') + 1), *driver.loc.back()); }
	// {CONFIG_SEC_UPDATE_TARGET_BY_ID}[ \t]+{FREE_TEXT_SPACE_COMMA_QUOTE}       { state_variable_from = 1; BEGIN(TRANSACTION_TO_VARIABLE); return p::make_CONFIG_SEC_RULE_UPDATE_TARGET_BY_ID(parserSanitizer(strchr(yytext, ' ') + 1), *driver.loc.back()); }
	// {CONFIG_SEC_UPDATE_ACTION_BY_ID}[ \t]+["]{FREE_TEXT_NEW_LINE}["]          { BEGIN(TRANSACTION_FROM_OPERATOR_TO_ACTIONS); return p::make_CONFIG_SEC_RULE_UPDATE_ACTION_BY_ID(parserSanitizer(strchr(yytext, ' ') + 1), *driver.loc.back()); }
	// {CONFIG_SEC_UPDATE_ACTION_BY_ID}[ \t]+{FREE_TEXT_SPACE_COMMA_QUOTE}       { BEGIN(TRANSACTION_FROM_OPERATOR_TO_ACTIONS); return p::make_CONFIG_SEC_RULE_UPDATE_ACTION_BY_ID(parserSanitizer(strchr(yytext, ' ') + 1), *driver.loc.back()); }
	// {DIRECTIVE_SECRULESCRIPT}[ \t]+{CONFIG_VALUE_PATH}                      { BEGIN(TRANSACTION_FROM_DIRECTIVE_TO_ACTIONS); return p::make_DIRECTIVE_SECRULESCRIPT(parserSanitizer(strchr(yytext, ' ') + 1), *driver.loc.back()); }
	// {DIRECTIVE_SECRULESCRIPT}[ \t]+["]{FREE_TEXT_SPACE_COMMA_QUOTE}["]      { BEGIN(TRANSACTION_FROM_DIRECTIVE_TO_ACTIONS); return p::make_DIRECTIVE_SECRULESCRIPT(parserSanitizer(strchr(yytext, ' ') + 1), *driver.loc.back()); }
	// {DIRECTIVE}                                                             { BEGIN(TRANSACTION_TO_VARIABLE); return p::make_DIRECTIVE(yytext, *driver.loc.back()); }
	// {CONFIG_DIR_SEC_DEFAULT_ACTION}                                         { BEGIN(TRANSACTION_FROM_DIRECTIVE_TO_ACTIONS); return p::make_CONFIG_DIR_SEC_DEFAULT_ACTION(yytext, *driver.loc.back()); }
	// {CONFIG_DIR_SEC_ACTION}                                                 { BEGIN(TRANSACTION_FROM_DIRECTIVE_TO_ACTIONS); return p::make_CONFIG_DIR_SEC_ACTION(yytext, *driver.loc.back()); }
	// #[ \t]*SecRule[^\\].*\\[ \t]*[\r\n]*                                    { driver.loc.back()->lines(1); driver.loc.back()->step(); BEGIN(COMMENT); }
	// #[ \t]*SecAction[^\\].*\\[ \t]*[^\\n]                                   { driver.loc.back()->lines(1); driver.loc.back()->step(); BEGIN(COMMENT);  }
	return lex
}
