package modsecurity

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Transaction struct {
	RuleSet *SecRuleSet
	Engine  *Engine
	Phase   int
	Abort   bool
	*NetInfo
	*Request
	*Response
	*Errors
	VariableCache map[string]interface{}
	intervention  *Intervention
}

type NetInfo struct {
	SrcIp   string
	SrcPort string
	DstIp   string
	DstPort string
}
type Request struct {
	URL    *url.URL
	Method string
	Proto  string
	Header http.Header
	Body   *buffer
}

type Response struct {
	Code   int
	Proto  string
	Header http.Header
	Body   *buffer
}
type Errors struct {
	RequestBodyError error
}

func NewTransaction(e *Engine, rs *SecRuleSet) (*Transaction, error) {
	if e == nil {
		return nil, errors.New("no engine")
	}
	if rs == nil {
		return nil, errors.New("no rule set")
	}
	reqBody, err := newBuffer(e.TmpPath, e.RequestBodyInMem, e.RequestBody)
	if err != nil {
		return nil, err
	}
	resBody, err := newBuffer(e.TmpPath, e.ResponseBody, e.ResponseBody)
	if err != nil {
		return nil, err
	}
	return &Transaction{
		RuleSet:       rs,
		Engine:        e,
		NetInfo:       &NetInfo{},
		Request:       &Request{Body: reqBody},
		Response:      &Response{Body: resBody},
		Errors:        &Errors{},
		VariableCache: make(map[string]interface{}),
	}, nil
}

func (t *Transaction) ProcessPhase(phase int) {
	t.Phase = phase
	t.RuleSet.ProcessPhase(t, phase)
}

func (t *Transaction) ProcessConnection(srcIp, srcPort, dstIp, dstPort string) {
	t.Phase = PhaseRequestHeaders
	t.SrcIp = srcIp
	t.SrcPort = srcPort
	t.DstIp = dstIp
	t.DstPort = dstPort
	t.ProcessPhase(PhaseConnection)
}
func (t *Transaction) ProcessRequestURL(u *url.URL, method, proto string) {
	t.URL = u
	t.Method = method
	t.Request.Proto = proto
}
func (t *Transaction) ProcessRequestHeader(h http.Header) {
	if h == nil {
		h = make(http.Header)
	}
	t.Request.Header = h
	t.ProcessPhase(PhaseRequestHeaders)
}
func (t *Transaction) AppendRequestBody(p []byte) error {
	_, err := t.Request.Body.Write(p)
	return err
}

func (t *Transaction) ProcessRequestBody() {
	t.ProcessPhase(PhaseRequestBody)
}

func (t *Transaction) ProcessResponseHeaders(code int, proto string, header http.Header) {
	if header == nil {
		header = make(http.Header)
	}
	t.Response.Code = code
	t.Response.Proto = proto
	t.Response.Header = header
	t.ProcessPhase(PhaseResponseHeaders)
}
func (t *Transaction) AppendResponseBody(p []byte) error {
	_, err := t.Response.Body.Write(p)
	return err
}

func (t *Transaction) ProcessResponseBody() {
	t.ProcessPhase(PhaseResponseBody)
}

func (t *Transaction) ProcessLogging() {
	t.ProcessPhase(PhaseLogging)
}

func (t *Transaction) Intervention() *Intervention {
	if t.intervention == nil {
		t.intervention = new(Intervention)
		t.intervention.Reset()
	}
	return t.intervention
}

func (t *Transaction) AbortWithError(code int, err error) {
	i := t.Intervention()
	i.Status = code
	i.Disruptive = true
	t.Logf("abort process with error %s", err.Error())
}

func (t *Transaction) AbortWithStatus(code int) {
	i := t.Intervention()
	i.Status = code
	i.Disruptive = true
}
func (t *Transaction) Result() *Intervention {
	i := t.Intervention().Copy()
	if !t.Abort {
		t.Intervention().Reset()
	}
	return i
}

func (t *Transaction) Logf(f string, val ...interface{}) {
	buffer := bytes.NewBuffer(nil)
	fmt.Fprintf(buffer, "[client %s:%s](phase %d)", t.SrcIp, t.SrcPort, t.Phase)
	fmt.Fprintf(buffer, f, val...)
	i := t.Intervention()
	i.Log = append(i.Log, buffer.String())
}

type Intervention struct {
	Status     int
	Pause      time.Duration
	Url        *url.URL
	Log        []string
	Disruptive bool
}

func (i *Intervention) Reset() {
	i.Status = 200
	i.Pause = 0
	i.Url = nil
	i.Log = nil
	i.Disruptive = false
}

func (i *Intervention) Copy() *Intervention {
	res := new(Intervention)
	*res = *i
	return res
}
