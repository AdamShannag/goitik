package goitik

type Store interface {
	GetAuthorizationPolicy() (*AuthorizationPolicy, error)
}
