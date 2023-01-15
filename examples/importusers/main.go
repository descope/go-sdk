package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/mgmt"
	"github.com/descope/go-sdk/descope/utils"
)

var descopeClient *descope.DescopeClient

func prepare() (err error) {
	if utils.GetProjectIDEnvVariable() == "" {
		// the projectID can be found in the Project section of the admin console: https://app.descope.com/settings/project
		return errors.New("the DESCOPE_PROJECT_ID environment variable must be set")
	}
	if utils.GetManagementKeyEnvVariable() == "" {
		// generate a management key in the Company section of the admin console: https://app.descope.com/settings/company
		return errors.New("the DESCOPE_MANAGEMENT_KEY environment variable must be set")
	}
	descopeClient, err = descope.NewDescopeClient()
	return err
}

type TenantMapping struct {
	TenantID string   `json:"tenantId"`
	Roles    []string `json:"roles"`
}

type User struct {
	LoginID     string          `json:"id"`
	Email       string          `json:"email"`
	Phone       string          `json:"phone"`
	DisplayName string          `json:"displayName"`
	Roles       []string        `json:"roles"`
	Tenants     []TenantMapping `json:"tenants"`
}

type Data struct {
	Users []*User `json:"users"`
}

func main() {
	if len(os.Args) != 2 || len(os.Args[1]) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: importusers <jsonfile>")
		os.Exit(1)
	}

	if err := prepare(); err != nil {
		fmt.Fprintln(os.Stderr, "Error creating DescopeClient:", err)
		os.Exit(1)
	}

	bytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading input file:", err)
		os.Exit(1)
	}

	data := Data{}
	if err := json.Unmarshal(bytes, &data); err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing input file:", err)
		os.Exit(1)
	}

	fmt.Println("Adding", len(data.Users), "users...")

	for _, user := range data.Users {
		fmt.Println("Adding user", user.LoginID, "("+user.DisplayName+")")

		tenants := []*mgmt.AssociatedTenant{}
		for _, curr := range user.Tenants {
			tenants = append(tenants, &mgmt.AssociatedTenant{TenantID: curr.TenantID, Roles: curr.Roles})
		}

		res, err := descopeClient.Management.User().Create(user.LoginID, user.Email, user.Phone, user.DisplayName, user.Roles, tenants)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error adding user:", err)
		} else {
			fmt.Printf("Added user: %v\n", res)
		}
	}
}
