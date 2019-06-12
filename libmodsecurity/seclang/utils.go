package seclang

func isBlank(c rune) bool    { return runeInSlice(c, []rune{' ', '\f', '\t', '\v'}) }
func isNewLine(c rune) bool  { return c == '\n' || c == '\r' }
func isDecimal(c rune) bool  { return '0' <= c && c <= '9' }
func isAlphabet(c rune) bool { return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') }
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
