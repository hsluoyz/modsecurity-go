package variables

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableRequestBasename() modsecurity.Variable {
	return &VariableRequestBasename{}
}

type VariableRequestBasename struct {
}

func (*VariableRequestBasename) Name() string {
	return "REQUEST_BASENAME"
}
func (*VariableRequestBasename) Include(string) error { return nil }
func (*VariableRequestBasename) Exclude(string) error { return nil }
func (*VariableRequestBasename) Fetch(t *modsecurity.Transaction) []string {
	if t.URL == nil {
		return nil
	}
	b := basename(t.URL.Path)
	return []string{b}
}
func basename(path string) string {
	if path == "" {
		return "/"
	}
	// Strip trailing slashes.
	for len(path) > 0 && isPathSeparator(path[len(path)-1]) {
		path = path[0 : len(path)-1]
	}
	if path == "" {
		return "/"
	}
	i := len(path) - 1
	for i >= 0 && !isPathSeparator(path[i]) {
		i--
	}
	if i >= 0 {
		path = path[i+1:]
	}
	if path == "" {
		return "/"
	}
	return path
}

func isPathSeparator(i byte) bool {
	return i == '\\' || i == '/'
}
