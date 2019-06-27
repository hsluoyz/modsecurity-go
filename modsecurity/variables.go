package modsecurity

import (
	"net/url"
	"regexp"
	"strconv"

	"github.com/senghoo/modsecurity-go/utils"
)

type Variable interface {
	Name() string
	Include(string) error
	Exclude(string) error
	Fetch(*Transaction) []string
}

func NewVariableRequestURI() Variable {
	return &VariableRequestURI{}
}

type VariableRequestURI struct {
}

func (*VariableRequestURI) Name() string {
	return "REQUEST_URI"
}
func (*VariableRequestURI) Include(string) error { return nil }
func (*VariableRequestURI) Exclude(string) error { return nil }
func (*VariableRequestURI) Fetch(t *Transaction) []string {
	if t.URL == nil {
		return nil
	}
	u := new(url.URL)
	*u = *t.URL
	u.Scheme = ""
	u.Host = ""
	u.Opaque = ""
	u.User = nil
	return []string{u.String()}
}

func NewVariableArgsGet() Variable {
	return &VariableArgsGet{
		filter: &filter{},
	}
}

type VariableArgsGet struct {
	*filter
}

func (*VariableArgsGet) Name() string {
	return "ARGS_GET"
}
func (v *VariableArgsGet) Fetch(t *Transaction) []string {
	if t.URL == nil {
		return nil
	}
	return v.filter.Fetch(t.URL.Query())
}

func NewVariableArgsGetNames() Variable {
	return &VariableArgsGetNames{
		filter: &filter{},
	}
}

type VariableArgsGetNames struct {
	*filter
}

func (*VariableArgsGetNames) Name() string {
	return "ARGS_GET_NAMES"
}
func (v *VariableArgsGetNames) Fetch(t *Transaction) []string {
	if t.URL == nil {
		return nil
	}
	return v.filter.Names(t.URL.Query())
}

func NewVariableArgsPost() Variable {
	return &VariableArgsPost{
		filter: &filter{},
	}
}

type VariableArgsPost struct {
	*filter
}

func (*VariableArgsPost) Name() string {
	return "ARGS_POST"
}
func (v *VariableArgsPost) Fetch(t *Transaction) []string {
	if !t.Engine.RequestBodyAccess || t.Request.Body.Len() == 0 {
		return nil
	}
	val, _ := url.ParseQuery(t.Request.Body.String())
	return v.filter.Fetch(val)
}

func NewVariableArgsPostNames() Variable {
	return &VariableArgsPostNames{
		filter: &filter{},
	}
}

type VariableArgsPostNames struct {
	*filter
}

func (*VariableArgsPostNames) Name() string {
	return "ARGS_POST_NAMES"
}
func (v *VariableArgsPostNames) Fetch(t *Transaction) []string {

	if !t.Engine.RequestBodyAccess || t.Request.Body.Len() == 0 {
		return nil
	}
	val, _ := url.ParseQuery(t.Request.Body.String())
	return v.filter.Names(val)
}

func NewCountVariable(v Variable) Variable {
	return &CountVariable{v}
}

type CountVariable struct {
	Variable
}

func (v *CountVariable) Fetch(t *Transaction) []string {
	return []string{strconv.Itoa(len(v.Variable.Fetch(t)))}
}

type filter struct {
	include      []string
	includeRegex []*regexp.Regexp
	exclude      []string
	excludeRegex []*regexp.Regexp
}

func isRegex(str string) bool {
	if len(str) < 2 {
		return false
	}
	return str[0] == '/' && str[len(str)-1] == '/'
}

func (f *filter) Include(s string) error {
	if isRegex(s) {
		re, err := regexp.Compile(s[1 : len(s)-1])
		if err != nil {
			return err
		}
		f.includeRegex = append(f.includeRegex, re)
		return nil
	}
	f.include = append(f.include, s)
	return nil
}
func (f *filter) Exclude(s string) error {
	if isRegex(s) {
		re, err := regexp.Compile(s[1 : len(s)-1])
		if err != nil {
			return err
		}
		f.excludeRegex = append(f.excludeRegex, re)
		return nil
	}
	f.exclude = append(f.exclude, s)
	return nil
}

func (f *filter) Fetch(vs map[string][]string) []string {
	var res []string
	withName := f.FetchWithNames(vs)
	for _, v := range withName {
		res = append(res, v...)
	}
	return res
}

func (f *filter) Names(vs map[string][]string) []string {
	var res []string
	withName := f.FetchWithNames(vs)
	for k, _ := range withName {
		res = append(res, k)
	}
	return res
}

func (f *filter) FetchWithNames(vs map[string][]string) map[string][]string {
	var res = make(map[string][]string)
	for k, v := range vs {
		if (f.include != nil && !utils.StringInSlice(k, f.include)) ||
			(f.includeRegex != nil && !utils.StringInRegexSlice(k, f.includeRegex)) {
			continue
		}
		if (f.exclude != nil && utils.StringInSlice(k, f.exclude)) ||
			(f.excludeRegex != nil && utils.StringInRegexSlice(k, f.excludeRegex)) {
			continue
		}
		res[k] = append(res[k], v...)
	}
	return res
}
