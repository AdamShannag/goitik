# Goitik

Goitik is a simple policy engine for enforcing access control in your applications. With Goitik,
you can easily manage rules based on roles and headers, providing a flexible way for role-based access control (RBAC).

## Features

- **Enforce Rules on Roles and Headers**: Define access rules that evaluate both user roles and headers.

- **Grouped Roles**: Organize roles into groups, making management easier and more efficient.

- **Condition Evaluation**: Conditions such as `equals`, `contains`, `startsWith`, and `endsWith` can be defined for each group.

- **Match Policy**: Choose between `all` or `any` match policies:
    - **All**: All groups of conditions must pass for access to be granted.
    - **Any**: Any group of conditions must pass for access to be granted.

- **Multi-Path Rules**: One rule can be enforced on multiple paths, simplifying your policy structure.

- **Allow and Deny Rules**: Define both allow and deny rules that follow the same structure for comprehensive access control.

## Installation

To install Goitik, use the following command:

```bash
go get github.com/AdamShannag/goitik
```

## Usage

### Engine Interface

The `Engine` interface defines the core methods for evaluating expressions and managing validators.

```go
type Engine interface {
    Evaluate(string, Data) error
    SetValidator(string, validator.Func)
}
```

#### Methods:
- **Evaluate(string, Data) error**: Evaluates the provided string against the specified data. This method returns an error if the evaluation fails.
- **SetValidator(string, validator.Func)**: Sets a custom validator in the engine by providing a key and the corresponding validation function.


### Engine Initialization

#### NewEngine

To initialize the engine, you can use the `NewEngine` function. This function requires a roles header key, a store implementation, and a path finder.

```go
func NewEngine(rolesHeaderKey string, store Store, finder path.Finder) Engine
```

##### Parameters:
- **rolesHeaderKey**: A string that specifies the key for roles in the header.
- **store**: An instance of a type that implements the `Store` interface:
    ```go
    type Store interface {
        GetAuthorizationPolicy() (*AuthorizationPolicy, error)
    }
    ```
- **finder**: An instance of a type that implements the `Finder` interface:
    ```go
    type Finder interface {
        Find(string, []string) bool
    }
    ```

#### Adding Custom Validators

To add custom validators to the `matchModeValidatorMap`, you can use the `SetValidator` method:

```go
func SetValidator(string, validator.Func)
```

##### Parameters:
- **key**: A string that identifies the validator.
- **validator**: A function of type `validator.Func` that performs validation.

#### Using the Default Engine

If you prefer a simpler setup and do not wish to manually set up validators or the pathfinder, you can use the `NewDefaultEngine` function:

```go
func NewDefaultEngine(rolesHeaderKey string, store Store) Engine
```

##### Parameters:
- **rolesHeaderKey**: A string for the roles header key.
- **store**: An instance of a type that implements the `Store` interface.

This approach initializes the engine with default validators and the default pathfinder, making it quick and easy to get started.

---

```go
package main

import (
  "encoding/json"
  "github.com/AdamShannag/goitik"
  "google.golang.org/grpc/metadata"
  "log"
  "os"
)

// static store, implements goitik.Store
type staticStore struct {
  policy goitik.AuthorizationPolicy
}

func (s staticStore) GetAuthorizationPolicy() (*goitik.AuthorizationPolicy, error) {
  return &s.policy, nil

}

func main() {
  policyFile, err := os.ReadFile("path_to_policy_file.json")
  if err != nil {
    log.Fatal(err)
  }

  var policy goitik.AuthorizationPolicy
  err = json.Unmarshal(policyFile, &policy)
  if err != nil {
    log.Fatal(err)
  }

  engine := goitik.NewDefaultEngine("roles", staticStore{
    policy,
  })

  err = engine.Evaluate("/api.v1.orders.GetOrder", metadataWithRoles("role-1", "role-2"))
  if err != nil {
    log.Fatal(err) // policy evaluation failed
  }
}

// you can use any type that implements this method Get(key string) []string
func metadataWithRoles(r ...string) metadata.MD {
  md := metadata.MD{}
  md.Set("roles", r...)
  return md
}

```

## Example Policy
```json
{
  "allow_rules": {
    "view-order-rule": {
      "paths": [
        "/api.v1.*.GetOrder",
        "/api.*.*.ListOrders"
      ],
      "roles": {
        "any": {
          "view-order-group": {
            "equals": [
              "View Orders"
            ]
          },
          "admin-group": {
            "equals": [
              "Admin"
            ]
          }
        }
      }
    },
    "create-order-rule": {
      "paths": [
        "/api.v1.order.CreateOrder"
      ],
      "roles": {
        "all": {
          "create-order-group": {
            "equals": [
              "Create Order"
            ]
          }
        }
      }
    },
    "update-order-rule": {
      "paths": [
        "/api.v1.order.UpdateOrder"
      ],
      "roles": {
        "all": {
          "update-order-group": {
            "equals": [
              "Update Order"
            ]
          }
        }
      }
    }
  },
  "deny_rules": {
    "view-order-rule": {
      "paths": [
        "/api.v1.order.GetOrder",
        "/api.v1.order.ListOrders",
        "/api.v1.order.CreateOrder"
      ],
      "roles": {
        "all": {
          "not-allowed-to-get-and-list": {
            "endsWith": [
              "-Manager"
            ]
          },
          "not-allowed-to-create": {
            "equals": [
              "Accountant"
            ]
          }
        }
      },
      "headers": {
        "all": {
          "username": {
            "startsWith": [
              "dan"
            ]
          }
        }
      }
    },
    "update-order-rule": {
      "paths": [
        "/api.v1.order.UpdateOrder"
      ],
      "roles": {
        "all": {
          "not-allowed-to-update": {
            "equals": [
              "Manager"
            ]
          }
        }
      }
    }
  }
}
```

### Benchmarks

Here are the benchmark results for the previous policy

| Benchmark                                      | Iterations | Time (ns/op) | Bytes Allocated | Allocations |
|------------------------------------------------|------------|---------------|------------------|-------------|
| BenchmarkEvaluate/Allow_GetOrder               | 2,168,786  | 499.6         | 16 B/op          | 1           |
| BenchmarkEvaluate/Allow_ListOrders             | 2,078,187  | 541.7         | 16 B/op          | 1           |
| BenchmarkEvaluate/Allow_CreateOrder            | 1,233,342  | 969.4         | 16 B/op          | 1           |
| BenchmarkEvaluate/Allow_UpdateOrder            | 1,524,856  | 982.0         | 16 B/op          | 1           |

If you need any further modifications or additional details, feel free to ask!
## Contributing

I welcome contributions! If you have suggestions, bug reports, or improvements, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE.MD) file for details.