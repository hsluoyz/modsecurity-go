package seclang

import (
	"fmt"
	"strings"
	"sync"
	"unicode"
)

type StateStack struct {
	items []int
	lock  sync.RWMutex
}

func NewStateStack() *StateStack {
	return &StateStack{}
}

func (s *StateStack) Push(i int) {
	s.lock.Lock()
	s.items = append(s.items, i)
	s.lock.Unlock()
}

func (s *StateStack) Pop() int {
	if len(s.items) == 0 {
		return StateInit
	}
	s.lock.Lock()
	item := s.items[len(s.items)-1]
	s.items = s.items[0 : len(s.items)-1]
	s.lock.Unlock()
	return item
}

func (s *StateStack) Top() int {
	if len(s.items) == 0 {
		return StateInit
	}
	s.lock.Lock()
	item := s.items[len(s.items)-1]
	s.lock.Unlock()
	return item

}

func toCaseInsensitiveRegex(s string) string {
	var b strings.Builder
	for _, l := range s {
		lower := unicode.ToLower(l)
		upper := unicode.ToUpper(l)
		if lower == upper {
			b.WriteRune(l)
		} else {
			b.WriteString("[")
			b.WriteRune(lower)
			b.WriteRune(upper)
			b.WriteString("]")
		}
	}
	return b.String()
}

func quotedOrNot(s string) string {
	return fmt.Sprintf(`((["]%s")|(%s))`, s, s)
}

func namedRegex(name, s string) string {
	return fmt.Sprintf("(?P<%s>%s)", name, s)
}

func removeQuotes(str string) string {
	str = strings.TrimSpace(str)
	for {
		if strlen := len(str); strlen >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
			str = str[1 : strlen-1]
		} else {
			break
		}
	}
	return str
}
