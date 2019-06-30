package variables

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableRequestFilename() modsecurity.Variable {
	return &VariableRequestFilename{}
}

type VariableRequestFilename struct {
}

func (*VariableRequestFilename) Name() string {
	return "REQUEST_FILENAME"
}
func (*VariableRequestFilename) Include(string) error { return nil }
func (*VariableRequestFilename) Exclude(string) error { return nil }
func (*VariableRequestFilename) Fetch(t *modsecurity.Transaction) []string {
	if t.URL == nil {
		return nil
	}
	return []string{t.URL.Path}
}
