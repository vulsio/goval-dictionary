package models

import (
	"strings"

	"github.com/ymomoi/goval-parser/oval"
)

func collectPacks(cri oval.Criteria) []Package {
	return walk(cri, []Package{})
}

func walk(cri oval.Criteria, acc []Package) []Package {
	for _, c := range cri.Criterions {
		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}
		acc = append(acc, Package{
			Name:    ss[0],
			Version: ss[1],
		})
	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walk(c, acc)
	}
	return acc
}
