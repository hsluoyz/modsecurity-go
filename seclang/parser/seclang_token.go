package parser

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
	TkVarXML
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
	TkActionBlock
	TkActionStatus
	TkActionpHase
	TkActionT
	TkActionSkip
	TkActionChain
	TkActionPhase
	TkActionVer
	TkActionLogData
	TkActionSetVar
	TkActionCapture
	TkActionPass
	// transform action
	TkTransLowercase
	TkTransUrlDecode
	TkTransUrlDecodeUni
	TkTransNone
	TkTransCompressWhitespace
	TkTransRemoveWhitespace
	TkTransReplaceNulls
	TkTransRemoveNulls
	TkEND
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
	"msg":      TkActionMsg,
	"id":       TkActionId,
	"tag":      TkActionTag,
	"rev":      TkActionRev,
	"ver":      TkActionVer,
	"severity": TkActionSeverity,
	"log":      TkActionLog,
	"deny":     TkActionDeny,
	"block":    TkActionBlock,
	"status":   TkActionStatus,
	"phase":    TkActionPhase,
	"t":        TkActionT,
	"skip":     TkActionSkip,
	"chain":    TkActionChain,
	"logdata":  TkActionLogData,
	"setvar":   TkActionSetVar,
	"capture":  TkActionCapture,
	"pass":     TkActionPass,
}
var transformationMap = map[string]int{
	"lowercase":          TkTransLowercase,
	"urlDecode":          TkTransUrlDecode,
	"urlDecodeUni":       TkTransUrlDecodeUni,
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
	"XML":                     TkVarXML,
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

	RegisterValue(TkValueDetc, `DetectionOnly`)
	RegisterValue(TkValueOff, `Off`)
	RegisterValue(TkValueOn, `On`)
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

func RegisterDir(tk int, name string, f DirectiveFactory) {
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

func RegisterValue(tk int, regex string) {
	Values[tk] = &ValueDesc{
		Regex: regex,
		Token: tk,
		regex: regexp.MustCompile(fmt.Sprintf("(?i)^%s$", regex)),
	}
}
