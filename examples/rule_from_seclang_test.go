package main

import (
	"net/url"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/seclang"
	"github.com/hsluoyz/modsecurity-go/utils"
)

func ExampleRuleFromSeclang() {
	rule := `SecRuleEngine On
                 SecRule REQUEST_URI '@rx cmd' \
                            "id:123,\
                             phase:2,\
                             t:lowercase,\
                             deny"`

	eng := modsecurity.NewEngine()
	rs, err := seclang.NewDireSetFromSecLangString(rule)
	if err != nil {
		panic(err)
	}
	err = rs.Execute(eng)
	if err != nil {
		panic(err)
	}

	ts, err := eng.NewTransaction()
	if err != nil {
		panic(err)
	}
	ts.ProcessConnection("127.0.0.1", "12345", "127.0.0.1", "80")
	u, err := url.Parse(`/search?="a';CMD echo '1"`)
	if err != nil {
		panic(err)
	}
	ts.ProcessRequestURL(u, "GET", "HTTP/1.1")
	ts.ProcessRequestHeader(nil)
	i := ts.Result()
	utils.Pprint(i)
	// Output:
	// (*modsecurity.Intervention)({
	//  Status: (int) 403,
	//  Pause: (time.Duration) 0s,
	//  Url: (*url.URL)(<nil>),
	//  Log: ([]string) (len=1 cap=1) {
	//   (string) (len=75) "[client 127.0.0.1:12345] (phase 2) ModSecurity: Access denied with code 403"
	//  },
	//  Disruptive: (bool) true
	// })
}
