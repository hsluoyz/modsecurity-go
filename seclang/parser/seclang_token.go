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
	TkVarArgsCombinedSize
	TkVarArgsGet
	TkVarArgsGetNames
	TkVarArgsNames
	TkVarArgsPost
	TkVarArgsPostNames
	TkVarDuration
	TkVarFiles
	TkVarFilesCombinedSize
	TkVarFilesNames
	TkVarFilesSizes
	TkVarFilesTmpNames
	TkVarFilesTmpContent
	TkVarFullRequest
	TkVarFullRequestLength
	TkVarMultipartFilename
	TkVarMultipartName
	TkVarGeo
	TkVarIp
	TkVarMatchedVars
	TkVarMatchedVarsNames
	TkVarQueryString
	TkVarRemoteAddr
	TkVarReqBodyProcessor
	TkVarRequestBasename
	TkVarRequestBody
	TkVarRequestCookies
	TkVarRequestCookiesNames
	TkVarRequestFilename
	TkVarRequestHeaders
	TkVarRequestHeadersNames
	TkVarRequestLine
	TkVarRequestMethod
	TkVarRequestProtocol
	TkVarRequestUri
	TkVarRequestUriRaw
	TkVarResponseBody
	TkVarResponseContentLength
	TkVarResponseContentType
	TkVarResponseHeaders
	TkVarResponseHeadersNames
	TkVarResponseProtocol
	TkVarResponseStatus
	TkVarTx
	TkVarUniqueId
	TkVarXML
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
	TkOpIpMatchFromFile
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
	TkTransBase64Decode
	TkTransBase64Encode
	TkTransCmdLine
	TkTransCompressWhitespace
	TkTransCssDecode
	TkTransEscapeSeqDecode
	TkTransHexDecode
	TkTransHexEncode
	TkTransHtmlEntityDecode
	TkTransJsDecode
	TkTransLength
	TkTransLowercase
	TkTransMd5
	TkTransNone
	TkTransNormalisePath
	TkTransNormalisePathWin
	TkTransNormalizePath
	TkTransNormalizePathWin
	TkTransParityEven7bit
	TkTransParityOdd7bit
	TkTransParityZero7bit
	TkTransRemoveComments
	TkTransRemoveCommentsChar
	TkTransRemoveNulls
	TkTransRemoveWhitespace
	TkTransReplaceComments
	TkTransReplaceNulls
	TkTransSha1
	TkTransSqlHexDecode
	TkTransTrim
	TkTransTrimLeft
	TkTransTrimRight
	TkTransUrlDecode
	TkTransUrlDecodeUni
	TkTransUrlEncode
	TkTransUtf8toUnicode
	TkEND
)

var OperatorMap = map[string]int{
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
	"ipMatchFromFile":      TkOpIpMatchFromFile,
	"geoLookup":            TkOpGeoLookup,
	"rbl":                  TkOpRbl,
	"detectXSS":            TkOpDetectXss,
	"detectSQLi":           TkOpDetectSqli,
}

var ActionMap = map[string]int{
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
var TransformationMap = map[string]int{
	"base64Decode":       TkTransBase64Decode,
	"base64Encode":       TkTransBase64Encode,
	"cmdLine":            TkTransCmdLine,
	"compressWhitespace": TkTransCompressWhitespace,
	"cssDecode":          TkTransCssDecode,
	"escapeSeqDecode":    TkTransEscapeSeqDecode,
	"hexDecode":          TkTransHexDecode,
	"hexEncode":          TkTransHexEncode,
	"htmlEntityDecode":   TkTransHtmlEntityDecode,
	"jsDecode":           TkTransJsDecode,
	"length":             TkTransLength,
	"lowercase":          TkTransLowercase,
	"md5":                TkTransMd5,
	"none":               TkTransNone,
	"normalisePath":      TkTransNormalisePath,
	"normalisePathWin":   TkTransNormalisePathWin,
	"normalizePath":      TkTransNormalizePath,
	"normalizePathWin":   TkTransNormalizePathWin,
	"parityEven7bit":     TkTransParityEven7bit,
	"parityOdd7bit":      TkTransParityOdd7bit,
	"parityZero7bit":     TkTransParityZero7bit,
	"removeComments":     TkTransRemoveComments,
	"removeCommentsChar": TkTransRemoveCommentsChar,
	"removeNulls":        TkTransRemoveNulls,
	"removeWhitespace":   TkTransRemoveWhitespace,
	"replaceComments":    TkTransReplaceComments,
	"replaceNulls":       TkTransReplaceNulls,
	"sha1":               TkTransSha1,
	"sqlHexDecode":       TkTransSqlHexDecode,
	"trim":               TkTransTrim,
	"trimLeft":           TkTransTrimLeft,
	"trimRight":          TkTransTrimRight,
	"urlDecode":          TkTransUrlDecode,
	"urlDecodeUni":       TkTransUrlDecodeUni,
	"urlEncode":          TkTransUrlEncode,
	"utf8toUnicode":      TkTransUtf8toUnicode,
}

var VariableMap = map[string]int{
	"ARGS":                    TkVarArgs,
	"ARGS_COMBINED_SIZE":      TkVarArgsCombinedSize,
	"ARGS_GET":                TkVarArgsGet,
	"ARGS_GET_NAMES":          TkVarArgsGetNames,
	"ARGS_NAMES":              TkVarArgsNames,
	"ARGS_POST":               TkVarArgsPost,
	"ARGS_POST_NAMES":         TkVarArgsPostNames,
	"DURATION":                TkVarDuration,
	"FILES":                   TkVarFiles,
	"FILES_COMBINED_SIZE":     TkVarFilesCombinedSize,
	"FILES_NAMES":             TkVarFilesNames,
	"FILES_SIZES":             TkVarFilesSizes,
	"FILES_TMPNAMES":          TkVarFilesTmpNames,
	"FILES_TMP_CONTENT":       TkVarFilesTmpContent,
	"FULL_REQUEST":            TkVarFullRequest,
	"FULL_REQUEST_LENGTH":     TkVarFullRequestLength,
	"MULTIPART_FILENAME":      TkVarMultipartFilename,
	"MULTIPART_NAME":          TkVarMultipartName,
	"GEO":                     TkVarGeo,
	"IP":                      TkVarIp,
	"MATCHED_VARS":            TkVarMatchedVars,
	"MATCHED_VARS_NAMES":      TkVarMatchedVarsNames,
	"QUERY_STRING":            TkVarQueryString,
	"REMOTE_ADDR":             TkVarRemoteAddr,
	"REQBODY_PROCESSOR":       TkVarReqBodyProcessor,
	"REQUEST_BASENAME":        TkVarRequestBasename,
	"REQUEST_BODY":            TkVarRequestBody,
	"REQUEST_COOKIES":         TkVarRequestCookies,
	"REQUEST_COOKIES_NAMES":   TkVarRequestCookiesNames,
	"REQUEST_FILENAME":        TkVarRequestFilename,
	"REQUEST_HEADERS":         TkVarRequestHeaders,
	"REQUEST_HEADERS_NAMES":   TkVarRequestHeadersNames,
	"REQUEST_LINE":            TkVarRequestLine,
	"REQUEST_METHOD":          TkVarRequestMethod,
	"REQUEST_PROTOCOL":        TkVarRequestProtocol,
	"REQUEST_URI":             TkVarRequestUri,
	"REQUEST_URI_RAW":         TkVarRequestUriRaw,
	"RESPONSE_BODY":           TkVarResponseBody,
	"RESPONSE_CONTENT_LENGTH": TkVarResponseContentLength,
	"RESPONSE_CONTENT_TYPE":   TkVarResponseContentType,
	"RESPONSE_HEADERS":        TkVarResponseHeaders,
	"RESPONSE_HEADERS_NAMES":  TkVarResponseHeadersNames,
	"RESPONSE_PROTOCOL":       TkVarResponseProtocol,
	"RESPONSE_STATUS":         TkVarResponseStatus,
	"TX":                      TkVarTx,
	"UNIQUE_ID":               TkVarUniqueId,
	"XML":                     TkVarXML,
}

var SeverityMap = map[string]int{
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

var PhaseAlias = map[string]int{
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
