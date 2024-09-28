package goitik

import (
	"encoding/json"
	"os"
	"testing"
)

type testStore struct {
	policy AuthorizationPolicy
}

func (t testStore) GetAuthorizationPolicy() (*AuthorizationPolicy, error) {
	return &t.policy, nil
}

type mockData map[string][]string

func (m mockData) Get(key string) []string {
	return m[key]
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name        string
		policyFile  string
		roles       []string
		expectedErr bool
	}{
		{
			name:        "Allow_Pass",
			policyFile:  "./testdata/new_structure_allow_policy.json",
			roles:       []string{"role-1", "role-2"},
			expectedErr: false,
		},
		{
			name:        "Deny_Pass",
			policyFile:  "./testdata/new_structure_deny_policy.json",
			roles:       []string{"role-3", "role-2"},
			expectedErr: false,
		},
		{
			name:        "Allow_Deny_Pass",
			policyFile:  "./testdata/new_structure_allow_deny_policy.json",
			roles:       []string{"role-1", "role-2"},
			expectedErr: false,
		},
		{
			name:        "Allow_Deny_Pass_Many",
			policyFile:  "./testdata/new_structure_allow_deny_policy_many.json",
			roles:       []string{"role-1", "role-2"},
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyFile, err := os.ReadFile(tt.policyFile)
			if err != nil {
				t.Fatal(err)
			}
			policy := AuthorizationPolicy{}
			err = json.Unmarshal(policyFile, &policy)
			if err != nil {
				t.Fatal(err)
			}

			engine := NewDefaultEngine("roles", testStore{
				policy,
			})

			err = engine.Evaluate("test.path", metadataWithRoles(tt.roles...))

			if (err != nil) != tt.expectedErr {
				t.Fatalf("expected error: %v, got: %v", tt.expectedErr, err)
			}
		})
	}
}

func BenchmarkEvaluate(b *testing.B) {
	tests := []struct {
		name       string
		policyFile string
		roles      []string
		path       string
	}{
		{
			name:       "Allow_GetOrder",
			policyFile: "./testdata/order_service_policy.json",
			roles:      []string{"View Orders"},
			path:       "/api.v1.test.GetOrder",
		},
		{
			name:       "Allow_ListOrders",
			policyFile: "./testdata/order_service_policy.json",
			roles:      []string{"Admin"},
			path:       "/api.v2.order.ListOrders",
		},
		{
			name:       "Allow_CreateOrder",
			policyFile: "./testdata/order_service_policy.json",
			roles:      []string{"Create Order"},
			path:       "/api.v1.order.CreateOrder",
		},
		{
			name:       "Allow_UpdateOrder",
			policyFile: "./testdata/order_service_policy.json",
			roles:      []string{"Update Order"},
			path:       "/api.v1.order.UpdateOrder",
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			policyFile, err := os.ReadFile(tt.policyFile)
			if err != nil {
				b.Fatal(err)
			}

			policy := AuthorizationPolicy{}
			err = json.Unmarshal(policyFile, &policy)
			if err != nil {
				b.Fatal(err)
			}

			engine := NewDefaultEngine("roles", testStore{
				policy,
			})

			roles := metadataWithRoles(tt.roles...)
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err = engine.Evaluate(tt.path, roles)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func metadataWithRoles(r ...string) mockData {
	md := mockData{}
	md["roles"] = r
	return md
}
