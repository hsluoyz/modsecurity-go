package variables

import (
	"mime/multipart"
	"net/url"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableArgsPostNames() modsecurity.Variable {
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
func (v *VariableArgsPostNames) Fetch(t *modsecurity.Transaction) []string {
	switch tp, parsed := requestBodyParse(t, bodyTypeUrlencoded, bodyTypeMultipart); tp {
	case bodyTypeUrlencoded:
		content, ok := parsed.(url.Values)
		if !ok {
			return nil
		}
		return v.filter.Names(content)
	case bodyTypeMultipart:
		content, ok := parsed.(*multipart.Form)
		if !ok {
			return nil
		}
		return v.filter.Names(content.Value)
	}
	return nil
}
