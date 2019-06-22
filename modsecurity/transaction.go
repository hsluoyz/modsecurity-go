package modsecurity

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Transaction struct {
	RuleSet        *SecRuleSet
	Engine         *Engine
	Phase          int
	SrcIp          string
	SrcPort        string
	DstIp          string
	DstPort        string
	URL            *url.URL
	Method         string
	RequestProto   string
	RequestHeader  http.Header
	RequestBody    *bytes.Buffer
	ResponseCode   int
	ResponseProto  string
	ResponseHeader http.Header
	ResponseBody   *bytes.Buffer
	intervention   *Intervention
}

func NewTransaction(e *Engine, rs *SecRuleSet) *Transaction {
	return &Transaction{
		RuleSet: rs,
		Engine:  e,
	}
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
	t.RequestProto = proto
}
func (t *Transaction) ProcessRequestHeader(h http.Header) {
	t.RequestHeader = h
	t.ProcessPhase(PhaseRequestHeaders)
}
func (t *Transaction) AppendRequestBody(p []byte) error {
	if t.RequestBody == nil {
		t.RequestBody = bytes.NewBuffer(nil)
	}
	_, err := t.RequestBody.Write(p)
	return err
}

func (t *Transaction) ProcessRequestBody() {
	t.ProcessPhase(PhaseRequestBody)
}

func (t *Transaction) ProcessResponseHeaders(code int, proto string, header http.Header) {
	t.ResponseCode = code
	t.ResponseProto = proto
	t.ResponseHeader = header
	t.ProcessPhase(PhaseResponseHeaders)
}
func (t *Transaction) AppendResponseBody(p []byte) error {
	if t.ResponseBody == nil {
		t.ResponseBody = bytes.NewBuffer(nil)
	}
	_, err := t.ResponseBody.Write(p)
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
func (t *Transaction) Result() *Intervention {
	i := t.Intervention().Copy()
	t.Intervention().Reset()
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
