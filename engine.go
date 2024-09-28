package goitik

import (
	"errors"
	"github.com/AdamShannag/goitik/path"
	"github.com/AdamShannag/goitik/validator"
	"slices"
)

type Engine interface {
	Evaluate(string, Data) error
	SetValidator(string, validator.Func)
}

type defaultEngine struct {
	rolesHeaderKey        string
	store                 Store
	matchModeValidatorMap map[string]validator.Func
	pathFinder            path.Finder
}

func NewEngine(rolesHeaderKey string, store Store, finder path.Finder) Engine {
	return &defaultEngine{
		rolesHeaderKey:        rolesHeaderKey,
		store:                 store,
		matchModeValidatorMap: make(map[string]validator.Func),
		pathFinder:            finder,
	}
}

func NewDefaultEngine(rolesHeaderKey string, store Store) Engine {
	return &defaultEngine{
		rolesHeaderKey: rolesHeaderKey,
		store:          store,
		matchModeValidatorMap: map[string]validator.Func{
			"equals":     validator.Equals,
			"startsWith": validator.StartsWith,
			"endsWith":   validator.EndsWith,
			"contains":   validator.Contains,
		},
		pathFinder: &path.DefaultFinder{},
	}
}

func (p *defaultEngine) SetValidator(key string, validator validator.Func) {
	p.matchModeValidatorMap[key] = validator
}

func (p *defaultEngine) Evaluate(method string, data Data) error {
	policy, storeErr := p.store.GetAuthorizationPolicy()
	if storeErr != nil {
		return storeErr
	}

	if err := p.shouldAllow(method, data, policy.AllowRules); err != nil {
		return err
	}

	if err := p.shouldDeny(method, data, policy.DenyRules); err != nil {
		return err
	}

	return nil
}

func (p *defaultEngine) shouldAllow(path string, data Data, rules Rules) error {
	for ruleName, rule := range rules.ForPath(path, p.pathFinder) {
		for k, v := range rule.Headers.All {
			if !p.validateCondition(data.Get(k), v) {
				return errors.New("policy evaluation failed: allow_rules.(" + ruleName + ").headers.all.(" + k + ") failed")
			}
		}

		if rule.Headers.Any != nil {
			validCondition := false
			for k, v := range rule.Headers.Any {
				if p.validateCondition(data.Get(k), v) {
					validCondition = true
					break
				}
			}

			if !validCondition {
				return errors.New("policy evaluation failed: allow_rules.(" + ruleName + ").headers.any failed")
			}
		}

		for k, v := range rule.Roles.All {
			if !p.validateCondition(data.Get(p.rolesHeaderKey), v) {
				return errors.New("policy evaluation failed: allow_rules.(" + ruleName + ").roles.all.(" + k + ") failed")
			}
		}

		if rule.Roles.Any != nil {
			validCondition := false
			for _, v := range rule.Roles.Any {
				if p.validateCondition(data.Get(p.rolesHeaderKey), v) {
					validCondition = true
					break
				}
			}

			if !validCondition {
				return errors.New("policy evaluation failed: allow_rules.(" + ruleName + ").roles.any failed")
			}
		}

	}

	return nil
}

func (p *defaultEngine) shouldDeny(path string, data Data, rules Rules) error {
	for ruleName, rule := range rules.ForPath(path, p.pathFinder) {
		for k, v := range rule.Headers.All {
			if p.validateCondition(data.Get(k), v) {
				return errors.New("policy evaluation failed: deny_rules.(" + ruleName + ").headers.all.(" + k + ") passed")
			}
		}

		if rule.Headers.Any != nil {
			validCondition := true
			for k, v := range rule.Roles.Any {
				if !p.validateCondition(data.Get(k), v) {
					validCondition = false
					break
				}
			}

			if validCondition {
				return errors.New("policy evaluation failed: deny_rules.(" + ruleName + ").headers.any failed")
			}
		}

		for k, v := range rule.Roles.All {
			if p.validateCondition(data.Get(p.rolesHeaderKey), v) {
				return errors.New("policy evaluation failed: deny_rules.(" + ruleName + ").roles.all.(" + k + ") passed")
			}
		}

		if rule.Roles.Any != nil {
			validCondition := true
			for _, v := range rule.Roles.Any {
				if !p.validateCondition(data.Get(p.rolesHeaderKey), v) {
					validCondition = false
					break
				}
			}

			if validCondition {
				return errors.New("policy evaluation failed: deny_rules.(" + ruleName + ").roles.any failed")
			}
		}
	}

	return nil
}

func (p *defaultEngine) validateCondition(tokenRoles []string, condition Condition) bool {
	for matchMode, roles := range condition {
		for _, requiredRole := range roles {
			if !slices.ContainsFunc(tokenRoles, func(role string) bool {
				return p.matchModeValidatorMap[matchMode](role, requiredRole)
			}) {
				return false
			}
		}
	}

	return true
}
