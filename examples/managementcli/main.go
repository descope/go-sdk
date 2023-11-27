package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/spf13/cobra"
	"github.com/tj/go-naturaldate"
)

// Command line flags

var flags struct {
	LoginID     string
	Email       string
	Phone       string
	Name        string
	Tenants     []string
	Domains     []string
	Description string
	Permissions []string
}

// Descope SDK

var descopeClient *client.DescopeClient

func prepare() (err error) {
	descopeConfig := &client.Config{
		ProjectID:      os.Getenv(descope.EnvironmentVariableProjectID),
		ManagementKey:  os.Getenv(descope.EnvironmentVariableManagementKey),
		DescopeBaseURL: os.Getenv(descope.EnvironmentVariableBaseURL),
	}
	if descopeConfig.ProjectID == "" {
		// the projectID can be found in the Project section of the admin console: https://app.descope.com/settings/project
		return errors.New("the DESCOPE_PROJECT_ID environment variable must be set")
	}
	if descopeConfig.ManagementKey == "" {
		// generate a management key in the Company section of the admin console: https://app.descope.com/settings/company
		return errors.New("the DESCOPE_MANAGEMENT_KEY environment variable must be set")
	}
	descopeClient, err = client.NewWithConfig(descopeConfig)
	return err
}

func userCreate(args []string) error {
	tenants := []*descope.AssociatedTenant{}
	for _, tenantID := range flags.Tenants {
		tenants = append(tenants, &descope.AssociatedTenant{TenantID: tenantID})
	}
	user := &descope.CreateUserRequest{}
	user.Email = "foo@bar.com"
	user.Phone = flags.Phone
	user.Name = flags.Name
	user.Tenants = tenants
	_, err := descopeClient.Management.User().Create(args[0], user)
	return err
}

func userUpdate(args []string) error {
	tenants := []*descope.AssociatedTenant{}
	for _, tenantID := range flags.Tenants {
		tenants = append(tenants, &descope.AssociatedTenant{TenantID: tenantID})
	}
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	user.Phone = flags.Phone
	user.Name = flags.Name
	user.Tenants = tenants

	_, err := descopeClient.Management.User().Update(args[0], user)
	return err
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

func userUpdateLoginID(args []string) error {
	res, err := descopeClient.Management.User().UpdateLoginID(args[0], args[1])
	if err == nil {
		fmt.Println("Updated user:", res)
	}
	return err
}

func userSearchAll(args []string) error {
	limit, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return err
	}

	page, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return err
	}

	res, err := descopeClient.Management.User().SearchAll(&descope.UserSearchOptions{Limit: int32(limit), Page: int32(page)})
	if err == nil {
		for _, u := range res {
			fmt.Println("Found:", u)
		}
	}
	return err
}

func setUserPassword(args []string) error {
	loginID := args[0]
	password := args[1]
	return descopeClient.Management.User().SetPassword(loginID, password)
}

func expireUserPassword(args []string) error {
	loginID := args[0]
	return descopeClient.Management.User().ExpirePassword(loginID)
}

func getUserProviderToken(args []string) error {
	loginID := args[0]
	provider := args[1]
	res, err := descopeClient.Management.User().GetProviderToken(loginID, provider)
	if err == nil {
		fmt.Println("Found:", res)
	}
	return err
}

func accessKeyCreate(args []string) error {
	tenants := []*descope.AssociatedTenant{}
	for _, tenantID := range flags.Tenants {
		tenants = append(tenants, &descope.AssociatedTenant{TenantID: tenantID})
	}
	expireTime, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return err
	}
	cleartext, res, err := descopeClient.Management.AccessKey().Create(args[0], expireTime, nil, tenants)
	if err != nil {
		return err
	}
	fmt.Println("Access Key Created with ID: ", res.ID)
	fmt.Println("Cleartext:", cleartext)
	return nil
}

func accessKeyLoad(args []string) error {
	res, err := descopeClient.Management.AccessKey().Load(args[0])
	if err == nil {
		fmt.Println("Found:", res)
	}
	return err
}

func accessKeySearchAll(args []string) error {
	res, err := descopeClient.Management.AccessKey().SearchAll(nil)
	if err == nil {
		for _, u := range res {
			fmt.Println("Found:", u)
		}
	}
	return err
}

func accessKeyUpdate(args []string) error {
	_, err := descopeClient.Management.AccessKey().Update(args[0], args[1])
	return err
}

func accessKeyDeactivate(args []string) error {
	return descopeClient.Management.AccessKey().Deactivate(args[0])
}

func accessKeyActivate(args []string) error {
	return descopeClient.Management.AccessKey().Activate(args[0])
}

func accessKeyDelete(args []string) error {
	return descopeClient.Management.AccessKey().Delete(args[0])
}

func tenantCreate(args []string) error {
	tr := &descope.TenantRequest{Name: args[0], SelfProvisioningDomains: flags.Domains}
	if flags.LoginID != "" {
		return descopeClient.Management.Tenant().CreateWithID(flags.LoginID, tr)
	}
	tenantID, err := descopeClient.Management.Tenant().Create(tr)
	if err == nil {
		fmt.Println("Created new tenant with id:", tenantID)
	}
	return err
}

func tenantUpdate(args []string) error {

	if flags.LoginID != "" {
		tr := &descope.TenantRequest{Name: args[0], SelfProvisioningDomains: flags.Domains}
		return descopeClient.Management.Tenant().CreateWithID(flags.LoginID, tr)
	}
	tr := &descope.TenantRequest{Name: args[1], SelfProvisioningDomains: flags.Domains}
	return descopeClient.Management.Tenant().Update(args[0], tr)
}

func tenantDelete(args []string) error {
	return descopeClient.Management.Tenant().Delete(args[0])
}

func tenantLoad(args []string) error {
	tenant, err := descopeClient.Management.Tenant().Load(args[0])
	if err == nil {
		fmt.Println("Found:", tenant)
	}
	return err
}

func tenantLoadAll(args []string) error {
	res, err := descopeClient.Management.Tenant().LoadAll()
	if err == nil {
		for _, t := range res {
			fmt.Println("Found:", t)
		}
	}
	return err
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

func groupAllForTenant(args []string) error {
	tenantID := args[0]
	res, err := descopeClient.Management.Group().LoadAllGroups(tenantID)
	if err == nil {
		for _, p := range res {
			fmt.Printf("Found group: %s, %s. Members: %v\n", p.ID, p.Display, p.Members)
		}
	}
	return err
}

func writeToFile(fileName string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(fileName, b, 0644)
}

func listFlows(args []string) error {
	res, err := descopeClient.Management.Flow().ListFlows()
	if err == nil {
		for _, f := range res.Flows {
			fmt.Printf("ID: %s, Name: %s, Description: %s, Disabled: %t\n", f.ID, f.Name, f.Description, f.Disabled)
		}
	}
	return err
}

func exportFlow(args []string) error {
	flowID := args[0]
	res, err := descopeClient.Management.Flow().ExportFlow(flowID)
	if err != nil {
		return err
	}
	err = writeToFile(fmt.Sprintf("%s.json", flowID), res)
	if err == nil {
		fmt.Printf("Found flow [%s] named %s with %d screens\n", res.Flow.ID, res.Flow.Name, len(res.Screens))
	}
	return err
}

func importFlow(args []string) error {
	fileName := args[0]
	flowID := args[1]
	b, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	data := &descope.FlowResponse{}
	err = json.Unmarshal(b, data)
	if err != nil {
		return err
	}

	res, err := descopeClient.Management.Flow().ImportFlow(flowID, data.Flow, data.Screens)
	if err == nil {
		fmt.Printf("Imported flow [%s] named %s with %d screens\n", res.Flow.ID, res.Flow.Name, len(res.Screens))
	}
	return err
}

func importTheme(args []string) error {
	fileName := args[0]
	b, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	data := &descope.Theme{}
	err = json.Unmarshal(b, data)
	if err != nil {
		return err
	}

	_, err = descopeClient.Management.Flow().ImportTheme(data)
	if err == nil {
		fmt.Println("Imported theme")
	}
	return err
}

func exportTheme(args []string) error {
	res, err := descopeClient.Management.Flow().ExportTheme()
	if err != nil {
		return err
	}
	err = writeToFile("theme.json", res)
	if err == nil {
		fmt.Println("Found theme")
	}
	return err
}

func groupAllForMembersUserIDs(args []string) error {
	tenantID := args[0]
	userIDs := strings.Split(args[1], ",")
	res, err := descopeClient.Management.Group().LoadAllGroupsForMembers(tenantID, userIDs, nil)
	if err == nil {
		for _, p := range res {
			fmt.Printf("Found group: %s, %s. Members: %v\n", p.ID, p.Display, p.Members)
		}
	}
	return err
}

func groupAllForMembersLoginIDs(args []string) error {
	tenantID := args[0]
	loginIDs := strings.Split(args[1], ",")
	res, err := descopeClient.Management.Group().LoadAllGroupsForMembers(tenantID, nil, loginIDs)
	if err == nil {
		for _, p := range res {
			fmt.Printf("Found group: %s, %s. Members: %v\n", p.ID, p.Display, p.Members)
		}
	}
	return err
}

func groupAllGroupMembers(args []string) error {
	tenantID := args[0]
	groupID := args[1]
	res, err := descopeClient.Management.Group().LoadAllGroupMembers(tenantID, groupID)
	if err == nil {
		for _, p := range res {
			fmt.Printf("Found group: %s, %s. Members: %v\n", p.ID, p.Display, p.Members)
		}
	}
	return err
}

func auditFullTextSearch(args []string) error {
	from, err := naturaldate.Parse(args[1], time.Now(), naturaldate.WithDirection(naturaldate.Past))
	if err != nil {
		return err
	}
	fmt.Println(from)
	res, err := descopeClient.Management.Audit().Search(&descope.AuditSearchOptions{Text: args[0], From: from})
	if err == nil {
		var b []byte
		b, err = json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	}
	return err
}

func authzLoadSchema(args []string) error {
	res, err := descopeClient.Management.Authz().LoadSchema()
	if err == nil {
		var b []byte
		b, err = json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	}
	return err
}

func authzSaveSchema(args []string) error {
	schemaFile, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var schema *descope.AuthzSchema
	err = json.Unmarshal(schemaFile, &schema)
	if err != nil {
		return err
	}
	oldSchema, err := descopeClient.Management.Authz().LoadSchema()
	if err != nil {
		return err
	}
	upgrade, err := strconv.ParseBool(args[1])
	if err != nil {
		return err
	}
	err = descopeClient.Management.Authz().SaveSchema(schema, upgrade)
	if err == nil {
		if oldSchema.Name != schema.Name {
			fmt.Printf("Schema %s upgraded to %s.\n", oldSchema.Name, schema.Name)
		} else {
			fmt.Printf("Schema %s saved.\n", schema.Name)
		}
	}
	return err
}

func authzHasRelation(args []string) error {
	res, err := descopeClient.Management.Authz().HasRelations([]*descope.AuthzRelationQuery{
		{
			Resource:           args[0],
			RelationDefinition: args[1],
			Namespace:          args[2],
			Target:             args[3],
		},
	})
	if err == nil {
		var b []byte
		b, err = json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	}
	return err
}

func authzAddRelation(args []string) error {
	err := descopeClient.Management.Authz().CreateRelations([]*descope.AuthzRelation{
		{
			Resource:           args[0],
			RelationDefinition: args[1],
			Namespace:          args[2],
			Target:             args[3],
		},
	})
	if err == nil {
		fmt.Println("Relation added.")
	}
	return err
}

func authzAddRelationTargetSet(args []string) error {
	err := descopeClient.Management.Authz().CreateRelations([]*descope.AuthzRelation{
		{
			Resource:                             args[0],
			RelationDefinition:                   args[1],
			Namespace:                            args[2],
			TargetSetResource:                    args[3],
			TargetSetRelationDefinition:          args[4],
			TargetSetRelationDefinitionNamespace: args[5],
		},
	})
	if err == nil {
		fmt.Println("Relation to target set added.")
	}
	return err
}

// Command line setup

var cli = &cobra.Command{
	Use:   "managementcli",
	Short: "A command line utility for working with the Descope management APIs",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return prepare()
	},
}

func addCommand(action func([]string) error, use string, help string, setup func(*cobra.Command)) {
	cmd := &cobra.Command{
		Use:   use,
		Short: help,
		Run: func(_ *cobra.Command, args []string) {
			if err := action(args); err != nil {
				fmt.Fprintln(os.Stderr, "The management operation failed:", err)
			}
		},
	}
	setup(cmd)
	cmd.DisableFlagsInUseLine = !cmd.HasLocalFlags()
	cmd.Flags().SortFlags = false
	cli.AddCommand(cmd)
}

func main() {
	addCommand(userCreate, "user-create <loginID>", "Create a new user", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.Flags().StringVarP(&flags.Email, "email", "E", "", "the user's email address")
		cmd.Flags().StringVarP(&flags.Phone, "phone", "P", "", "the user's phone number")
		cmd.Flags().StringVarP(&flags.Name, "name", "N", "", "the user's display name")
		cmd.Flags().StringSliceVarP(&flags.Tenants, "tenants", "T", nil, "the ids of the user's tenants")
	})

	addCommand(userUpdate, "user-update <loginID>", "Update an existing user", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.Flags().StringVarP(&flags.Email, "email", "E", "", "the user's email address")
		cmd.Flags().StringVarP(&flags.Phone, "phone", "P", "", "the user's phone number")
		cmd.Flags().StringVarP(&flags.Name, "name", "N", "", "the user's display name")
		cmd.Flags().StringSliceVarP(&flags.Tenants, "tenants", "T", nil, "the ids of the user's tenants")
	})

	addCommand(userDelete, "user-delete <loginID>", "Delete an existing user", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(accessKeyCreate, "access-key-create <name> <expireTime>", "Create a new access key", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
		cmd.Flags().StringSliceVarP(&flags.Tenants, "tenants", "T", nil, "the ids of the user's tenants")
	})

	addCommand(accessKeyLoad, "access-key-load", "Load an access key <id>", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(accessKeySearchAll, "access-key-search-all", "Search all access keys", func(cmd *cobra.Command) {
	})

	addCommand(accessKeyUpdate, "access-key-update", "Update an access key <id> <name>", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
	})

	addCommand(accessKeyDeactivate, "access-key-deactivate", "Deactivate an access key <id>", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(accessKeyActivate, "access-key-activate", "Activate an access key <id>", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(accessKeyDelete, "access-key-delete", "Delete an access key <id>", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(tenantCreate, "tenant-create <name>", "Create a new tenant", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.Flags().StringVarP(&flags.LoginID, "id", "I", "", "the tenant's custom id")
		cmd.Flags().StringSliceVarP(&flags.Domains, "domains", "D", nil, "the tenant's self provisioning domains")
	})

	addCommand(tenantUpdate, "tenant-update <id> <name>", "Update an existing tenant", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
		cmd.Flags().StringSliceVarP(&flags.Domains, "domains", "D", nil, "the tenant's self provisioning domains")
	})

	addCommand(tenantDelete, "tenant-delete <id>", "Delete an existing tenant", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(tenantLoad, "tenant-load", "Load tenant by id", func(cmd *cobra.Command) {
	})

	addCommand(tenantLoadAll, "tenant-all", "Load all tenants", func(cmd *cobra.Command) {
	})

	addCommand(userLoad, "user-load <id>", "Load an existing user", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(userUpdateLoginID, "user-update-loginid <id> <new-id>", "Update loginid of user", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
	})

	addCommand(userSearchAll, "user-search-all", "Search existing users", func(cmd *cobra.Command) {
		// Currently not accepting any filters
		cmd.Args = cobra.ExactArgs(2)
	})

	addCommand(setUserPassword, "user-set-password <loginId> <password>", "Set user password (The password will be initially set as expired)", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
	})

	addCommand(expireUserPassword, "user-expire-password <loginId>", "Expire user password", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(getUserProviderToken, "user-provider-token <loginId> <provider>", "Get user provider token", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
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
	})

	addCommand(permissionAll, "permission-all", "Load all permissions", func(cmd *cobra.Command) {
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
	})

	addCommand(roleAll, "role-all", "Load all roles", func(cmd *cobra.Command) {
	})

	addCommand(groupAllForTenant, "group-all-for-tenant <tenantId>", "Load all groups for a given tenant id", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(listFlows, "list-flows", "List all flows in project", func(cmd *cobra.Command) {
	})

	addCommand(exportFlow, "export-flow <flowId>", "Export the flow and screens for a given flow id", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(importFlow, "import-flow <fileName> <flowId>", "load flow and screens from given fileName and import as flowId", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
	})

	addCommand(exportTheme, "export-theme", "Export the theme for the project", func(cmd *cobra.Command) {
	})

	addCommand(importTheme, "import-theme <fileName>", "Import a theme for the project", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
	})

	addCommand(groupAllForMembersUserIDs, "group-all-for-members-user-ids <tenantId> <userIDs>", "Load all groups for the given user's ID (can be found in the user's JWT)", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
	})

	addCommand(groupAllForMembersLoginIDs, "group-all-for-members-loginIDs <tenantId> <loginIDs>", "Load all groups for the given user's loginIDs (used for sign-in)", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
	})

	addCommand(groupAllGroupMembers, "group-members <tenantId> <groupId>", "Load all group's members by the given group id", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
	})

	addCommand(auditFullTextSearch, "audit-search <text> <from>", "Full text search up to last 30 days of audit. From can be specified in plain English (last 5 minutes, last day)", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
	})

	addCommand(authzLoadSchema, "authz-load-schema", "Load and display the current AuthZ ReBAC schema", func(cmd *cobra.Command) {
	})

	addCommand(authzSaveSchema, "authz-save-schema <filename> <upgrade>", "Save (and potentially upgrade) the AuthZ ReBAC schema from the given file", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(2)
	})

	addCommand(authzHasRelation, "authz-has-relation <resource> <relationDefinition> <namespace> <target>", "Check if the given relation exists", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(4)
	})

	addCommand(authzAddRelation, "authz-add-relation <resource> <relationDefinition> <namespace> <target>", "Add a relation from a resource to a given target", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(4)
	})

	addCommand(authzAddRelationTargetSet, "authz-add-relation-targetset <resource> <relationDefinition> <namespace> <targetset-resource> <targetset-rd> <targetset-ns>", "Add a relation from a resource to a given target set", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(6)
	})

	err := cli.Execute()
	if err != nil {
		os.Exit(1)
	}
}
