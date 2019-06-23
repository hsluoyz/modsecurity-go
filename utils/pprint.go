package utils

import "github.com/davecgh/go-spew/spew"

func Pprint(v interface{}) {
	pprint := spew.NewDefaultConfig()
	pprint.DisablePointerAddresses = true
	pprint.Dump(v)
}
