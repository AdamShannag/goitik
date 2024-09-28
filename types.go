package goitik

import (
	"github.com/AdamShannag/goitik/path"
	"iter"
)

type Data interface {
	Get(key string) []string
}

type Rules map[string]Rule
type Condition map[string][]string
type Conditions map[string]Condition

type AuthorizationPolicy struct {
	AllowRules Rules `json:"allow_rules,omitempty"`
	DenyRules  Rules `json:"deny_rules,omitempty"`
}

type Rule struct {
	Paths   []string    `json:"paths"`
	Roles   MatchPolicy `json:"roles,omitempty"`
	Headers MatchPolicy `json:"headers,omitempty"`
}

type MatchPolicy struct {
	All Conditions `json:"all,omitempty"`
	Any Conditions `json:"any,omitempty"`
}

func (r Rules) ForPath(path string, finder path.Finder) iter.Seq2[string, Rule] {
	return func(yield func(string, Rule) bool) {
		for name, rule := range r {
			if !finder.Find(path, rule.Paths) {
				continue
			}
			if !yield(name, rule) {
				return
			}
		}
	}
}
