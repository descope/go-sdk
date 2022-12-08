package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/mgmt"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/spf13/cobra"
)

// Command line flags

var flags struct {
	Identifier  string
	Email       string
	Phone       string
	Name        string
	Tenants     []string
	Domains     []string
	Description string
	Permissions []string
}

// Descope SDK

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

func userCreate(args []string) error {
	tenants := []mgmt.UserTenants{}
	for _, tenantID := range flags.Tenants {
		tenants = append(tenants, mgmt.UserTenants{TenantID: tenantID})
	}
	return descopeClient.Management.User().Create(args[0], flags.Email, flags.Phone, flags.Name, nil, tenants)
}

func userUpdate(args []string) error {
	tenants := []mgmt.UserTenants{}
	for _, tenantID := range flags.Tenants {
		tenants = append(tenants, mgmt.UserTenants{TenantID: tenantID})
	}
	return descopeClient.Management.User().Update(args[0], flags.Email, flags.Phone, flags.Name, nil, tenants)
}

func userDelete(args []string) error {
	return descopeClient.Management.User().Delete(args[0])
}

func userLoad(args []string) error {
	res, err := descopeClient.Management.User().Load(args[0])
	if err == nil {
		fmt.Println("Found:", res)
	}
	return err
}

func userSearchAll(args []string) error {
	res, err := descopeClient.Management.User().SearchAll(nil, nil, 0)
	if err == nil {
		for _, u := range res {
			fmt.Println("Found:", u)
		}
	}
	return err
}

func tenantCreate(args []string) error {
	if flags.Identifier != "" {
		return descopeClient.Management.Tenant().CreateWithID(flags.Identifier, args[0], flags.Domains)
	}
	tenantID, err := descopeClient.Management.Tenant().Create(args[0], flags.Domains)
	if err == nil {
		fmt.Println("Created new tenant with id:", tenantID)
	}
	return err
}

func tenantUpdate(args []string) error {
	if flags.Identifier != "" {
		return descopeClient.Management.Tenant().CreateWithID(flags.Identifier, args[0], flags.Domains)
	}
	return descopeClient.Management.Tenant().Update(args[0], args[1], flags.Domains)
}

func tenantDelete(args []string) error {
	return descopeClient.Management.Tenant().Delete(args[0])
}

func permissionCreate(args []string) error {
	return descopeClient.Management.Permission().Create(args[0], flags.Description)
}

func permissionUpdate(args []string) error {
	return descopeClient.Management.Permission().Update(args[0], args[1], flags.Description)
}

func permissionDelete(args []string) error {
	return descopeClient.Management.Permission().Delete(args[0])
}

func permissionAll(args []string) error {
	res, err := descopeClient.Management.Permission().LoadAll()
	if err == nil {
		for _, p := range res {
			fmt.Println("Found:", p)
		}
	}
	return err
}

func roleCreate(args []string) error {
	return descopeClient.Management.Role().Create(args[0], flags.Description, flags.Permissions)
}

func roleUpdate(args []string) error {
	return descopeClient.Management.Role().Update(args[0], args[1], flags.Description, flags.Permissions)
}

func roleDelete(args []string) error {
	return descopeClient.Management.Role().Delete(args[0])
}

func roleAll(args []string) error {
	res, err := descopeClient.Management.Role().LoadAll()
	if err == nil {
		for _, p := range res {
			fmt.Println("Found:", p)
		}
	}
	return err
}

// Command line setup

var cli = &cobra.Command{
	Use:               "managementcli",
	Short:             "A command line utility for working with the Descope management APIs",
	CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return prepare()
	},
}

func addCommand(action func([]string) error, use string, help string, setup func(*cobra.Command)) {
	command := &cobra.Command{
		Use:   use,
		Short: help,
		Run: func(_ *cobra.Command, args []string) {
			if err := action(args); err != nil {
				fmt.Fprintln(os.Stderr, "The management operation failed:", err)
			}
		},
	}
	setup(command)
	command.Flags().SortFlags = false
	cli.AddCommand(command)
}

func main() {
	addCommand(userCreate, "user-create <identifier>", "Create a new user", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.Flags().StringVarP(&flags.Email, "email", "E", "", "the user's email address")
		cmd.Flags().StringVarP(&flags.Phone, "phone", "P", "", "the user's phone number")
		cmd.Flags().StringVarP(&flags.Name, "name", "N", "", "the user's display name")
		cmd.Flags().StringSliceVarP(&flags.Tenants, "tenants", "T", nil, "the ids of the user's tenants")
	})

	addCommand(userUpdate, "user-update <identifier>", "Update an existing user", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.Flags().StringVarP(&flags.Email, "email", "E", "", "the user's email address")
		cmd.Flags().StringVarP(&flags.Phone, "phone", "P", "", "the user's phone number")
		cmd.Flags().StringVarP(&flags.Name, "name", "N", "", "the user's display name")
		cmd.Flags().StringSliceVarP(&flags.Tenants, "tenants", "T", nil, "the ids of the user's tenants")
	})

	addCommand(userDelete, "user-delete <identifier>", "Delete an existing user", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.DisableFlagsInUseLine = true
	})

	addCommand(tenantCreate, "tenant-create <name>", "Create a new tenant", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.Flags().StringVarP(&flags.Identifier, "id", "I", "", "the tenant's custom id")
		cmd.Flags().StringSliceVarP(&flags.Domains, "domains", "D", nil, "the tenant's self provisioning domains")
	})

	addCommand(tenantUpdate, "tenant-update <id> <name>", "Update an existing tenant", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
		cmd.Flags().StringSliceVarP(&flags.Domains, "domains", "D", nil, "the tenant's self provisioning domains")
	})

	addCommand(tenantDelete, "tenant-delete <id>", "Delete an existing tenant", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.DisableFlagsInUseLine = true
	})

	addCommand(userLoad, "user-load <id>", "Load an existing user", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.DisableFlagsInUseLine = true
	})

	addCommand(userSearchAll, "user-search-all", "Search existing users", func(cmd *cobra.Command) {
		// Currently not accepting any filters
		cmd.DisableFlagsInUseLine = true
	})

	addCommand(permissionCreate, "permission-create <name>", "Create a new permission", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.Flags().StringVarP(&flags.Description, "description", "D", "", "the permission's description")
	})

	addCommand(permissionUpdate, "permission-update <name> <newName>", "Update a permission", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
		cmd.Flags().StringVarP(&flags.Description, "description", "D", "", "the permission's description")
	})

	addCommand(permissionDelete, "permission-delete <name>", "Delete a permission", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.DisableFlagsInUseLine = true
	})

	addCommand(permissionAll, "permission-all", "Load all permissions", func(cmd *cobra.Command) {
		cmd.DisableFlagsInUseLine = true
	})

	addCommand(roleCreate, "role-create <name>", "Create a new role", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.Flags().StringVarP(&flags.Description, "description", "D", "", "the role's description")
		cmd.Flags().StringSliceVarP(&flags.Permissions, "permissions", "P", nil, "the permission names included in this role")
	})

	addCommand(roleUpdate, "role-update <name> <newName>", "Update a role", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
		cmd.Flags().StringVarP(&flags.Description, "description", "D", "", "the role's description")
		cmd.Flags().StringSliceVarP(&flags.Permissions, "permissions", "P", nil, "the permission names included in this role")
	})

	addCommand(roleDelete, "role-delete <name>", "Delete a role", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.DisableFlagsInUseLine = true
	})

	addCommand(roleAll, "role-all", "Load all roles", func(cmd *cobra.Command) {
		cmd.DisableFlagsInUseLine = true
	})

	err := cli.Execute()
	if err != nil {
		os.Exit(1)
	}
}
