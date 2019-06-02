package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	fi, err := os.Open("tokens.txt")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	defer fi.Close()

	br := bufio.NewReader(fi)
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		strLine := strings.TrimSpace(string(line))
		if len(strLine) == 0 {
			continue
		}
		sp := strings.SplitN(strLine, " ", 2)
		if len(sp) < 2 {
			fmt.Printf("skip: %s\n", strLine)
			continue
		}
		name := sp[0]
		value := strings.TrimSpace(sp[1])
		// fmt.Println(covertName(name))
		fmt.Printf("%s: %s,\n", covertName(name), covertValue(value))

	}
}

func covertName(s string) string {
	var ns []string
	sp := strings.Split(s, "_")
	for _, s := range sp {
		ns = append(ns, strings.Title(strings.ToLower(s)))
	}
	return "Tk" + strings.Join(ns, "")
}

func covertValue(s string) string {
	casePrefix := "(?i:"
	if strings.HasPrefix(s, casePrefix) {
		return "`(" + strings.TrimPrefix(s, casePrefix) + "`"
	}
	return "`" + s + "`"
}
