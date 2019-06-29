package variables

import (
	"mime/multipart"
	"net/url"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableArgsPost() modsecurity.Variable {
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
func (v *VariableArgsPost) Fetch(t *modsecurity.Transaction) []string {
	switch tp, parsed := requestBodyParse(t, bodyTypeUrlencoded, bodyTypeMultipart); tp {
	case bodyTypeUrlencoded:
		content, ok := parsed.(url.Values)
		if content == nil || !ok {
			return nil
		}
		return v.filter.Fetch(content)
	case bodyTypeMultipart:
		content, ok := parsed.(*multipart.Form)
		if content == nil || !ok {
			return nil
		}
		return v.filter.Fetch(content.Value)
	}
	return nil
}
