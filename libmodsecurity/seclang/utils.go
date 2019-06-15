package seclang

import (
	"strings"
)

func isBlank(c rune) bool    { return runeInSlice(c, []rune{' ', '\f', '\t', '\v'}) }
func isNewLine(c rune) bool  { return c == '\n' || c == '\r' }
func isDecimal(c rune) bool  { return '0' <= c && c <= '9' }
func isAlphabet(c rune) bool { return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') }
func isQuote(c rune) bool    { return '\'' == c || '"' == c }
func runeInString(c rune, str string) bool {
	for _, r := range str {
		if r == c {
			return true
		}
	}
	return false
}

func runeInSlice(c rune, sli []rune) bool {
	for _, r := range sli {
		if r == c {
			return true
		}
	}
	return false
}

func trimQuote(s string) string {
	if len(s) >= 2 && isQuote(rune(s[0])) && isQuote(rune(s[len(s)-1])) {
		return s[1 : len(s)-1]
	}
	return s
}

func splitMulti(s string, seps string) []string {
	var count = 1
	if len(seps) == 0 {
		return []string{s}
	}
	for _, sep := range seps {
		count += strings.Count(s, string(sep))
	}
	res := make([]string, count)
	i := 0
	for {
		m := strings.IndexAny(s, seps)
		if m < 0 {
			break
		}
		res[i] = s[:m]
		s = s[m+1:]
		i++
	}
	res[i] = s
	return res[:i+1]

}
