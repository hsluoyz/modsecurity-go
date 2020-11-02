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
	TkValueElse
	TkValueOff
	TkValueOn
	// variables
	TkVarArgs
	TkVarArgsGet
	TkVarArgsGetNames
	TkVarArgsPost
	TkVarArgsPostNames
	TkVarArgsCombinedSize
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
	TkVarRequestUriRaw
	TkVarRequestLine
	TkVarReqBodyProcessor
	TkVarResponseBody
	TkVarResponseContentLength
	TkVarResponseContentType
	TkVarResponseHeaders
	TkVarResponseHeadersNames
	TkVarResponseProtocol
	TkVarResponseStatus
	TkVarXML
	TkVarTx
	TkVarFilesNames
	TkVarFiles
	TkVarFilesCombinedSize
	TkVarUniqueId
	TkVarDuration
	TkVarIp
	TkVarGeo
	TkVarMatchedVars
	TkVarMatchedVarsNames
	// operator
	TkOpRx
	TkOpEq
	TkOpGe
	TkOpGt
	TkOpLe
	TkOpLt
	TkOpValidateUrlEncoding
	TkOpValidateUtf8Encoding
	TkOpValidateByteRange
	TkOpPm
	TkOpPmFromFile
	TkOpWithin
	TkOpBeginsWith
	TkOpEndsWith
	TkOpContains
	TkOpStrEq
	TkOpIpMatch
	TkOpGeoLookup
	TkOpRbl
	TkOpDetectXss
	TkOpDetectSqli
	// actions
	TkActionAllow
	TkActionMsg
	TkActionId
	TkActionTag
	TkActionRev
	TkActionSeverity
	TkActionLog
	TkActionNoLog
	TkActionDeny
	TkActionBlock
	TkActionStatus
	TkActionpHase
	TkActionT
	TkActionSkip
	TkActionSkipAfter
	TkActionChain
	TkActionPhase
	TkActionVer
	TkActionLogData
	TkActionSetVar
	TkActionCapture
	TkActionPass
	TkActionCtl
	TkActionAuditLog
	TkActionNoAuditLog
	TkActionExpireVar
	TkActionDrop
	TkActionMultiMatch
	// transform action
	TkTransLowercase
	TkTransUrlDecode
	TkTransUrlDecodeUni
	TkTransNone
	TkTransCompressWhitespace
	TkTransRemoveWhitespace
	TkTransReplaceNulls
	TkTransRemoveNulls
	TkTransLength
	TkTransHtmlEntityDecode
	TkTransSha1
	TkTransHexEncode
	TkTransUtf8toUnicode
	TkTransCmdLine
	TkTransNormalisePath
	TkTransNormalizePath
	TkTransNormalizePathWin
	TkTransReplaceComments
	TkTransRemoveComments
	TkTransBase64Decode
	TkTransJsDecode
	TkTransCssDecode
	TkEND
)

var operatorMap = map[string]int{
	"rx":                   TkOpRx,
	"eq":                   TkOpEq,
	"ge":                   TkOpGe,
	"gt":                   TkOpGt,
	"le":                   TkOpLe,
	"lt":                   TkOpLt,
	"validateUrlEncoding":  TkOpValidateUrlEncoding,
	"validateUtf8Encoding": TkOpValidateUtf8Encoding,
	"validateByteRange":    TkOpValidateByteRange,
	"pm":                   TkOpPm,
	"pmFromFile":           TkOpPmFromFile,
	"within":               TkOpWithin,
	"beginsWith":           TkOpBeginsWith,
	"endsWith":             TkOpEndsWith,
	"contains":             TkOpContains,
	"streq":                TkOpStrEq,
	"ipMatch":              TkOpIpMatch,
	"geoLookup":            TkOpGeoLookup,
	"rbl":                  TkOpRbl,
	"detectXSS":            TkOpDetectXss,
	"detectSQLi":           TkOpDetectSqli,
}

var actionMap = map[string]int{
	"allow":      TkActionAllow,
	"msg":        TkActionMsg,
	"id":         TkActionId,
	"tag":        TkActionTag,
	"rev":        TkActionRev,
	"ver":        TkActionVer,
	"severity":   TkActionSeverity,
	"log":        TkActionLog,
	"nolog":      TkActionNoLog,
	"deny":       TkActionDeny,
	"block":      TkActionBlock,
	"status":     TkActionStatus,
	"phase":      TkActionPhase,
	"t":          TkActionT,
	"skip":       TkActionSkip,
	"skipAfter":  TkActionSkipAfter,
	"chain":      TkActionChain,
	"logdata":    TkActionLogData,
	"setvar":     TkActionSetVar,
	"capture":    TkActionCapture,
	"pass":       TkActionPass,
	"ctl":        TkActionCtl,
	"auditlog":   TkActionAuditLog,
	"noauditlog": TkActionNoAuditLog,
	"expirevar":  TkActionExpireVar,
	"drop":       TkActionDrop,
	"multiMatch": TkActionMultiMatch,
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
	"length":             TkTransLength,
	"htmlEntityDecode":   TkTransHtmlEntityDecode,
	"sha1":               TkTransSha1,
	"hexEncode":          TkTransHexEncode,
	"utf8toUnicode":      TkTransUtf8toUnicode,
	"cmdLine":            TkTransCmdLine,
	"normalisePath":      TkTransNormalisePath,
	"normalizePath":      TkTransNormalizePath,
	"normalizePathWin":   TkTransNormalizePathWin,
	"replaceComments":    TkTransReplaceComments,
	"removeComments":     TkTransRemoveComments,
	"base64Decode":       TkTransBase64Decode,
	"jsDecode":           TkTransJsDecode,
	"cssDecode":          TkTransCssDecode,
}

var variableMap = map[string]int{
	"ARGS":                    TkVarArgs,
	"ARGS_NAMES":              TkVarArgsNames,
	"ARGS_GET":                TkVarArgsGet,
	"ARGS_GET_NAMES":          TkVarArgsGetNames,
	"ARGS_POST":               TkVarArgsPost,
	"ARGS_POST_NAMES":         TkVarArgsPostNames,
	"ARGS_COMBINED_SIZE":      TkVarArgsCombinedSize,
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
	"REQUEST_URI_RAW":         TkVarRequestUriRaw,
	"REQUEST_LINE":            TkVarRequestLine,
	"REQBODY_PROCESSOR":       TkVarReqBodyProcessor,
	"RESPONSE_BODY":           TkVarResponseBody,
	"RESPONSE_CONTENT_LENGTH": TkVarResponseContentLength,
	"RESPONSE_CONTENT_TYPE":   TkVarResponseContentType,
	"RESPONSE_HEADERS":        TkVarResponseHeaders,
	"RESPONSE_HEADERS_NAMES":  TkVarResponseHeadersNames,
	"RESPONSE_PROTOCOL":       TkVarResponseProtocol,
	"RESPONSE_STATUS":         TkVarResponseStatus,
	"XML":                     TkVarXML,
	"TX":                      TkVarTx,
	"FILES_NAMES":             TkVarFilesNames,
	"FILES":                   TkVarFiles,
	"FILES_COMBINED_SIZE":     TkVarFilesCombinedSize,
	"UNIQUE_ID":               TkVarUniqueId,
	"DURATION":                TkVarDuration,
	"IP":                      TkVarIp,
	"GEO":                     TkVarGeo,
	"MATCHED_VARS":            TkVarMatchedVars,
	"MATCHED_VARS_NAMES":      TkVarMatchedVarsNames,
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

	RegisterValue(TkValueElse, `DetectionOnly`)
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
