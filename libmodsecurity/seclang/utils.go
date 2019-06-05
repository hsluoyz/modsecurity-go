package seclang

import "sync"

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
