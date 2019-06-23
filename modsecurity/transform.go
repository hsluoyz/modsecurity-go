package modsecurity

import "strings"

type Trans interface {
	Name() string
	Trans(string) string
}

type TransLowerCase struct{}

func NewTransLowerCase() Trans {
	return &TransLowerCase{}
}

func (*TransLowerCase) Name() string {
	return "lowercase"
}
func (*TransLowerCase) Trans(s string) string {
	return strings.ToLower(s)
}
