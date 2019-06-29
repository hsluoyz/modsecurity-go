package variables

import (
	"testing"

	"github.com/senghoo/modsecurity-go/utils"
)

func TestFilter(t *testing.T) {
	var input = map[string][]string{
		"a1": []string{"1"},
		"a2": []string{"2"},
		"b1": []string{"3"},
		"b2": []string{"4"},
	}

	t.Run("all", func(t *testing.T) {
		f := &filter{}
		res := f.Fetch(input)
		if !utils.SameStringSlice(res, []string{"1", "2", "3", "4"}) {
			t.Errorf("variable filter include fail got %q", res)
		}
	})
	t.Run("include", func(t *testing.T) {
		f := &filter{}
		f.Include("a1")
		res := f.Fetch(input)
		if !utils.SameStringSlice(res, []string{"1"}) {
			t.Errorf("variable filter include fail got %q", res)
		}
	})
	t.Run("include regex", func(t *testing.T) {
		f := &filter{}
		f.Include("/^a/")
		res := f.Fetch(input)
		if !utils.SameStringSlice(res, []string{"1", "2"}) {
			t.Errorf("variable filter include fail got %q", res)
		}
	})
	t.Run("exclude", func(t *testing.T) {
		f := &filter{}
		f.Exclude("b1")
		res := f.Fetch(input)
		if !utils.SameStringSlice(res, []string{"1", "2", "4"}) {
			t.Errorf("variable filter include fail got %q", res)
		}
	})
	t.Run("exclude regex", func(t *testing.T) {
		f := &filter{}
		f.Exclude("/b/")
		res := f.Fetch(input)
		if !utils.SameStringSlice(res, []string{"1", "2"}) {
			t.Errorf("variable filter include fail got %q", res)
		}
	})

	t.Run("include and exclude", func(t *testing.T) {
		f := &filter{}
		f.Include("/^a/")
		f.Exclude("a2")
		res := f.Fetch(input)
		if !utils.SameStringSlice(res, []string{"1"}) {
			t.Errorf("variable filter include fail got %q", res)
		}
	})
}