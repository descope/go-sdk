package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/google/uuid"
)

func main() {
	//startTime := time.Now()
	descopeClient, err := client.NewWithConfig(&client.Config{
		DescopeBaseURL:      "https://localhost:8443",
		FGACacheURL:         "http://authzcache.localhost:8000",
		ProjectID:           "",
		SessionJWTViaCookie: true,
		LogLevel:            logger.LogDebugLevel})
	if err != nil {
		panic(err)
	}

	// FGA
	fga := descopeClient.Management.FGA()
	relation := &descope.FGARelation{
		Resource:     "pikachu" + uuid.New().String(),
		Target:       "ash",
		Relation:     "owner",
		ResourceType: "doc",
		TargetType:   "user",
	}
	//SSO Settings
	//descopeClient.Management.User().SearchAll(context.TODO(), &descope.UserSearchOptions{})
	//descopeClient.Management.SSO().LoadSettings(context.TODO(), "T2sLQIjeNvIBZgALTRKij14zEfp0")
	//sso, err := descopeClient.Management.SSOApplication().Load(context.TODO(), "bla")

	//1st check (false)
	// checks, _ := fga.Check(context.TODO(), []*descope.FGARelation{relation})
	// printJSON("checks", checks)
	// //1st check repeated (false - from cache)
	// checks, _ = fga.Check(context.TODO(), []*descope.FGARelation{relation})
	// printJSON("checks", checks)
	// //create relation
	// _ = fga.CreateRelations(context.TODO(), []*descope.FGARelation{relation})
	// //2nd check (true)
	// checks, _ = fga.Check(context.TODO(), []*descope.FGARelation{relation})
	// printJSON("checks", checks)
	// //2nd check repeated (true - from cache)
	// checks, _ = fga.Check(context.TODO(), []*descope.FGARelation{relation})
	// printJSON("checks", checks)
	// //delete relation
	// _ = fga.DeleteRelations(context.TODO(), []*descope.FGARelation{relation})
	// //3rd check (false)
	// checks, _ = fga.Check(context.TODO(), []*descope.FGARelation{relation})
	// printJSON("checks", checks)
	// //3rd check repeated (false - from cache)
	// checks, _ = fga.Check(context.TODO(), []*descope.FGARelation{relation})
	// printJSON("checks", checks)
	// //extra create+delete+create
	//_ = fga.CreateRelations(context.TODO(), []*descope.FGARelation{relation})
	//_ = fga.CreateRelations(context.TODO(), []*descope.FGARelation{relation})
	//_ = fga.DeleteRelations(context.TODO(), []*descope.FGARelation{relation})
	_ = fga.CreateRelations(context.TODO(), []*descope.FGARelation{relation})
	relation.Resource = "pikachu" + uuid.New().String()
	_ = fga.CreateRelations(context.TODO(), []*descope.FGARelation{relation})
	checks, _ := fga.Check(context.TODO(), []*descope.FGARelation{
		{
			Resource:     "folder1",
			Target:       "user1",
			Relation:     "owner",
			ResourceType: "folder",
			TargetType:   "user",
		},
		{
			Resource:     "folder1",
			Target:       "u3",
			Relation:     "owner",
			ResourceType: "folder",
			TargetType:   "user",
		},
		{
			Resource:     "owners",
			Target:       "u3",
			Relation:     "member",
			ResourceType: "org",
			TargetType:   "user",
		},
	})
	printJSON("checks", checks)

	// sleep for 1 second to allow cache to expire
	//time.Sleep(5 * time.Second)
	//_, _ = descopeClient.Management.Authz().GetModified(context.TODO(), startTime)

	//save schema
	// 	_ = fga.SaveSchema(context.TODO(), &descope.FGASchema{
	// 		Schema: `model AuthZ 1.0

	// type user
	//   relation owner: file

	// type file
	// `,
	//
	//	})
}

func printJSON(title string, res any) {
	fmt.Println(title)
	json, _ := json.MarshalIndent(res, "", " ")
	println(string(json))
}
