package seclang

import (
	"fmt"
	"regexp"
	"strings"
)

const TkStart = 128

const (
	// directives
	TkDirRule = iota + TkStart
	TkDirRuleEng
	TkDirReqBody
	TkDirResBody
	TkValueDetc
	TkValueOff
	TkValueOn
	// variables
	TkVarArgs
	TkVarArgsNames
	TkVarQueryString
	TkVarRemoteAddr
	TkVarRequestBasename
	TkVarRequestBody
	TkVarRequestCookies
	TkVarRequestCookiesNames
	TkVarRequestFilename
	TkVarRequestHeaders
	TkVarRequestHeadersNames
	TkVarRequestMethod
	TkVarRequestProtocol
	TkVarRequestUri
	TkVarResponseBody
	TkVarResponseContentLength
	TkVarResponseContentType
	TkVarResponseHeaders
	TkVarResponseHeadersNames
	TkVarResponseProtocol
	TkVarResponseStatus
	// operator
	TkOpRx
	TkOpEq
	TkOpGe
	TkOpGt
	TkOpLe
	TkOpLt
	// actions
	TkActionAllow
	TkActionMsg
	TkActionId
	TkActionTag
	TkActionRev
	TkActionSeverity
	TkActionLog
	TkActionDeny
	TkActionbLock
	TkActionStatus
	TkActionpHase
	TkActionT
	TkActionSkip
	TkActionChain
	TkActionPhase
	// transform action
	TkTransLowercase
	TkTransUrlDecode
	TkTransNone
	TkTransCompressWhitespace
	TkTransRemoveWhitespace
	TkTransReplaceNulls
	TkTransRemoveNulls
)

var operatorMap = map[string]int{
	"rx": TkOpRx,
	"eq": TkOpEq,
	"ge": TkOpGe,
	"gt": TkOpGt,
	"le": TkOpLe,
	"lt": TkOpLt,
}

var actionMap = map[string]int{
	"allow":    TkActionAllow,
	"sg":       TkActionMsg,
	"id":       TkActionId,
	"ev":       TkActionRev,
	"severity": TkActionSeverity,
	"og":       TkActionLog,
	"deny":     TkActionDeny,
	"lock":     TkActionbLock,
	"statu":    TkActionStatus,
	"hase":     TkActionpHase,
	"t":        TkActionT,
	"kip":      TkActionSkip,
	"chain":    TkActionChain,
	"phase":    TkActionPhase,
}
var transformationMap = map[string]int{
	"lowercase":          TkTransLowercase,
	"urlDecode":          TkTransUrlDecode,
	"none":               TkTransNone,
	"compressWhitespace": TkTransCompressWhitespace,
	"removeWhitespace":   TkTransRemoveWhitespace,
	"replaceNulls":       TkTransReplaceNulls,
	"removeNulls":        TkTransRemoveNulls,
}

var variableMap = map[string]int{
	"ARGS":                    TkVarArgs,
	"ARGS_NAMES":              TkVarArgsNames,
	"QUERY_STRING":            TkVarQueryString,
	"REMOTE_ADDR":             TkVarRemoteAddr,
	"REQUEST_BASENAME":        TkVarRequestBasename,
	"REQUEST_BODY":            TkVarRequestBody,
	"REQUEST_COOKIES":         TkVarRequestCookies,
	"REQUEST_COOKIES_NAMES":   TkVarRequestCookiesNames,
	"REQUEST_FILENAME":        TkVarRequestFilename,
	"REQUEST_HEADERS":         TkVarRequestHeaders,
	"REQUEST_HEADERS_NAMES":   TkVarRequestHeadersNames,
	"REQUEST_METHOD":          TkVarRequestMethod,
	"REQUEST_PROTOCOL":        TkVarRequestProtocol,
	"REQUEST_URI":             TkVarRequestUri,
	"RESPONSE_BODY":           TkVarResponseBody,
	"RESPONSE_CONTENT_LENGTH": TkVarResponseContentLength,
	"RESPONSE_CONTENT_TYPE":   TkVarResponseContentType,
	"RESPONSE_HEADERS":        TkVarResponseHeaders,
	"RESPONSE_HEADERS_NAMES":  TkVarResponseHeadersNames,
	"RESPONSE_PROTOCOL":       TkVarResponseProtocol,
	"RESPONSE_STATUS":         TkVarResponseStatus,
}

var severityMap = map[string]int{
	"EMERGENCY": 0,
	"ALERT":     1,
	"CRITICAL":  2,
	"ERROR":     3,
	"WARNING":   4,
	"NOTICE":    5,
	"INFO":      6,
	"DEBUG":     7,
}

const (
	PhaseRequestHeaders  = 1
	PhaseRequestBody     = 2
	PhaseResponseHeaders = 3
	PhaseResponseBody    = 4
	PhaseLogging         = 5
)

var phaseAlias = map[string]int{
	"request":  PhaseRequestBody,
	"response": PhaseResponseBody,
	"logging":  PhaseLogging,
}

type DirectiveFactory func(*Scanner) (Directive, error)

type DirectiveDesc struct {
	Token int
	Val   string
	Func  DirectiveFactory
}

type ValueDesc struct {
	Token int
	Regex string
	regex *regexp.Regexp
}

func init() {
	Values = make(map[int]*ValueDesc)

	registerValue(TkValueDetc, `DetectionOnly`)
	registerValue(TkValueOff, `Off`)
	registerValue(TkValueOn, `On`)
}

var Directives map[int]*DirectiveDesc
var Values map[int]*ValueDesc
var dirIndex map[string]int

func DirectiveFromString(str string) *DirectiveDesc {
	token, has := dirIndex[strings.ToLower(str)]
	if !has {
		return nil
	}
	return Directives[token]
}

func registerDir(tk int, name string, f DirectiveFactory) {
	if Directives == nil {
		Directives = make(map[int]*DirectiveDesc)
	}
	Directives[tk] = &DirectiveDesc{
		Val:   name,
		Func:  f,
		Token: tk,
	}
	if dirIndex == nil {
		dirIndex = make(map[string]int)
	}
	dirIndex[strings.ToLower(name)] = tk
}

func registerValue(tk int, regex string) {
	Values[tk] = &ValueDesc{
		Regex: regex,
		Token: tk,
		regex: regexp.MustCompile(fmt.Sprintf("(?i)^%s$", regex)),
	}
}
