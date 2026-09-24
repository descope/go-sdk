// End-to-end walkthrough of the family account management API.
//
// Creates throwaway attribute definitions, a family, a guardian and a dependent, exercises every
// family endpoint, then deletes everything it created and restores the original family settings.
//
// Run (see README.md):
//
//	DESCOPE_PROJECT_ID=... DESCOPE_MANAGEMENT_KEY=... go run .
//
// Optional:
//
//	SKIP_CLEANUP=1   - keep everything the run created (and the guardian's membership) for inspection.
//	DESCOPE_BASE_URL - override the Descope API base URL (e.g. for a custom domain).
//	FAMILY_ROLE      - the guardian's role in the family. Defaults to "Family Admin", the default family
//	                   role Descope creates when family accounts are enabled. A different role needs the
//	                   "Family Impersonate Dependents" permission for the impersonation step to pass.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/descope/go-sdk/descope/sdk"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "\nFAILED:", err)
		os.Exit(1)
	}
}

// step prints the outcome of a call and its result, and returns the call's error.
func step(name string, result any, err error) error {
	if err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	fmt.Printf("\nOK %s\n", name)
	if result != nil {
		if b, err := json.MarshalIndent(result, "  ", "  "); err == nil {
			fmt.Println("  " + string(b))
		}
	}
	return nil
}

// tryStep is like step, but a failure is only logged (used for cleanup).
func tryStep(name string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED %s: %v\n", name, err)
		return
	}
	fmt.Printf("\nOK %s\n", name)
}

func run(ctx context.Context) error {
	projectID := os.Getenv(descope.EnvironmentVariableProjectID)
	managementKey := os.Getenv(descope.EnvironmentVariableManagementKey)
	if projectID == "" || managementKey == "" {
		return errors.New("the DESCOPE_PROJECT_ID and DESCOPE_MANAGEMENT_KEY environment variables must be set")
	}
	descopeClient, err := client.NewWithConfig(&client.Config{
		ProjectID:      projectID,
		ManagementKey:  managementKey,
		DescopeBaseURL: os.Getenv(descope.EnvironmentVariableBaseURL),
	})
	if err != nil {
		return fmt.Errorf("failed to create the Descope client: %w", err)
	}
	family := descopeClient.Management.Family()
	user := descopeClient.Management.User()

	// The default family role; it carries the "Family Impersonate Dependents" permission that
	// ImpersonateDependent requires
	guardianRole := os.Getenv("FAMILY_ROLE")
	if guardianRole == "" {
		guardianRole = "Family Admin"
	}
	// Keep everything the run created so it can be inspected in the console afterwards
	skipCleanup := os.Getenv("SKIP_CLEANUP") == "1"

	// Unique suffix so reruns and parallel runs don't collide
	runID := strconv.FormatInt(time.Now().UnixMilli(), 36)
	familyAttr := "plan_" + runID
	familyScopedAttr := "nickname_" + runID
	guardianLoginID := "guardian-" + runID + "@example.com"

	// --- Settings --------------------------------------------------------------------------------
	originalSettings, err := family.GetSettings(ctx)
	if err = step("Family().GetSettings", originalSettings, err); err != nil {
		return err
	}
	enabled, allowMultiple := true, true
	settings, err := family.ConfigureSettings(ctx, &descope.FamilySettingsRequest{Enabled: &enabled, AllowMultipleFamiliesUsers: &allowMultiple})
	if err = step("Family().ConfigureSettings (enable families)", settings, err); err != nil {
		return err
	}

	var familyID, dependentUserID string
	var guardianCreated, familyAttrCreated, familyScopedAttrCreated bool

	defer func() {
		if skipCleanup {
			fmt.Println("\n--- SKIP_CLEANUP=1, left in place ---")
			fmt.Println("  family ID:                   ", familyID)
			if familyAttrCreated {
				fmt.Println("  family attribute:            ", familyAttr)
			}
			if familyScopedAttrCreated {
				fmt.Println("  family-scoped user attribute:", familyScopedAttr)
			}
			if guardianCreated {
				fmt.Println("  guardian login ID:           ", guardianLoginID)
			}
			fmt.Println("  dependent user ID:           ", dependentUserID)
			fmt.Printf("  original settings:            %+v\n", *originalSettings)
			return
		}
		cleanup(ctx, family, user, dependentUserID, guardianCreated, guardianLoginID, familyID,
			familyScopedAttrCreated, familyScopedAttr, familyAttrCreated, familyAttr, originalSettings)
	}()

	// --- Attribute definitions -------------------------------------------------------------------
	// Type 1 = text. Family attributes live on the family entity; family-scoped attributes are user
	// attributes whose values are stored per family membership.
	attrs, err := family.CreateCustomAttributes(ctx, []*descope.CustomAttribute{{Name: familyAttr, Type: 1, DisplayName: "Plan"}})
	if err = step("Family().CreateCustomAttributes", attrs, err); err != nil {
		return err
	}
	familyAttrCreated = true
	attrs, err = family.GetCustomAttributes(ctx)
	if err = step("Family().GetCustomAttributes", attrs, err); err != nil {
		return err
	}

	attrs, err = user.CreateFamilyScopedCustomAttributes(ctx, []*descope.CustomAttribute{{Name: familyScopedAttr, Type: 1, DisplayName: "Nickname"}})
	if err = step("User().CreateFamilyScopedCustomAttributes", attrs, err); err != nil {
		return err
	}
	familyScopedAttrCreated = true
	attrs, err = user.GetFamilyScopedCustomAttributes(ctx)
	if err = step("User().GetFamilyScopedCustomAttributes", attrs, err); err != nil {
		return err
	}

	// --- Family CRUD -----------------------------------------------------------------------------
	created, err := family.Create(ctx, &descope.FamilyRequest{
		Name:             "Demo Family " + runID,
		CustomAttributes: map[string]any{familyAttr: "free"},
	})
	if err = step("Family().Create", created, err); err != nil {
		return err
	}
	familyID = created.ID

	newName := "Demo Family " + runID + " (renamed)"
	updated, err := family.Update(ctx, familyID, &descope.UpdateFamilyRequest{
		Name:             &newName,
		CustomAttributes: map[string]any{familyAttr: "premium"},
	})
	if err = step("Family().Update (rename + change attribute)", updated, err); err != nil {
		return err
	}
	families, err := family.SearchAll(ctx, &descope.FamilySearchOptions{IDs: []string{familyID}})
	if err = step("Family().SearchAll by ID", families, err); err != nil {
		return err
	}
	families, err = family.SearchAll(ctx, &descope.FamilySearchOptions{CustomAttributes: map[string]any{familyAttr: "premium"}})
	if err = step("Family().SearchAll by custom attribute", families, err); err != nil {
		return err
	}

	// --- Guardian (regular member) ---------------------------------------------------------------
	// A user can be created straight into a family, or added later with User().AddFamilies.
	guardianReq := &descope.UserRequest{}
	guardianReq.Email = guardianLoginID
	guardianReq.Name = "Demo Guardian"
	guardianReq.FamilyAssociations = []*descope.AssociatedFamily{{
		FamilyID:               familyID,
		Roles:                  []string{guardianRole},
		FamilyScopedAttributes: map[string]any{familyScopedAttr: "Mom"},
	}}
	guardian, err := user.Create(ctx, guardianLoginID, guardianReq)
	if err = step("User().Create (guardian, created into the family)", guardian, err); err != nil {
		return err
	}
	guardianCreated = true

	// AddFamilies on a family the user already belongs to merges - here it updates the nickname only
	guardian, err = user.AddFamilies(ctx, guardianLoginID, []*descope.AssociatedFamily{{
		FamilyID:               familyID,
		FamilyScopedAttributes: map[string]any{familyScopedAttr: "Mommy"},
	}})
	if err = step("User().AddFamilies (update family-scoped attribute)", userFamilies(guardian), err); err != nil {
		return err
	}

	// --- Dependent (shadow profile, no credentials) ----------------------------------------------
	dependent, err := family.CreateDependent(ctx, familyID, &descope.FamilyDependentRequest{
		User:                   descope.User{Name: "Demo Kid " + runID, GivenName: "Demo"},
		FamilyScopedAttributes: map[string]map[string]any{familyID: {familyScopedAttr: "Kiddo"}},
	})
	if err = step("Family().CreateDependent", dependent, err); err != nil {
		return err
	}
	dependentUserID = dependent.UserID
	if len(dependent.LoginIDs) == 0 {
		return errors.New("the created dependent has no login ID")
	}

	// --- Search users by family ------------------------------------------------------------------
	members, total, err := user.SearchAll(ctx, &descope.UserSearchOptions{FamilyIDs: []string{familyID}})
	memberLoginIDs := [][]string{}
	for _, member := range members {
		memberLoginIDs = append(memberLoginIDs, member.LoginIDs)
	}
	if err = step(fmt.Sprintf("User().SearchAll (all family members, total %d)", total), memberLoginIDs, err); err != nil {
		return err
	}
	isDependent := true
	dependents, total, err := user.SearchAll(ctx, &descope.UserSearchOptions{FamilyIDs: []string{familyID}, Dependent: &isDependent})
	dependentIDs := []string{}
	for _, d := range dependents {
		dependentIDs = append(dependentIDs, d.UserID)
	}
	if err = step(fmt.Sprintf("User().SearchAll (dependents only, total %d)", total), dependentIDs, err); err != nil {
		return err
	}

	// --- Impersonation ---------------------------------------------------------------------------
	// The guardian acts as family admin through guardianRole's impersonate-dependents permission
	jwt, err := family.ImpersonateDependent(ctx, guardianLoginID, dependent.LoginIDs[0], familyID)
	if err = step("Family().ImpersonateDependent", nil, err); err != nil {
		return err
	}
	// sub is the dependent, act is the guardian acting on their behalf, dcf is the selected family
	printSessionClaims(jwt)
	guardianJWT, err := family.StopImpersonation(ctx, jwt, nil, 0)
	if err = step("Family().StopImpersonation", nil, err); err != nil {
		return err
	}
	// Back to the guardian's own session: sub is the guardian and act is gone
	printSessionClaims(guardianJWT)

	// --- Membership removal ----------------------------------------------------------------------
	// Kept when skipping cleanup, so the family shows both the guardian and the dependent
	if !skipCleanup {
		guardian, err = user.RemoveFamilies(ctx, guardianLoginID, []string{familyID})
		if err = step("User().RemoveFamilies (guardian)", userFamilies(guardian), err); err != nil {
			return err
		}
	}
	return nil
}

// cleanup deletes everything the run created, in reverse order, and restores the original settings.
func cleanup(ctx context.Context, family sdk.Family, user sdk.User, dependentUserID string, guardianCreated bool, guardianLoginID string,
	familyID string, familyScopedAttrCreated bool, familyScopedAttr string, familyAttrCreated bool, familyAttr string, originalSettings *descope.FamilySettings) {
	fmt.Println("\n--- cleanup ---")
	if dependentUserID != "" {
		tryStep("Family().DeleteDependent", family.DeleteDependent(ctx, dependentUserID))
	}
	if guardianCreated {
		tryStep("User().Delete (guardian)", user.Delete(ctx, guardianLoginID))
	}
	if familyID != "" {
		tryStep("Family().Delete", family.Delete(ctx, familyID))
	}
	if familyScopedAttrCreated {
		_, err := user.DeleteFamilyScopedCustomAttributes(ctx, []string{familyScopedAttr})
		tryStep("User().DeleteFamilyScopedCustomAttributes", err)
	}
	if familyAttrCreated {
		_, err := family.DeleteCustomAttributes(ctx, []string{familyAttr})
		tryStep("Family().DeleteCustomAttributes", err)
	}
	_, err := family.ConfigureSettings(ctx, &descope.FamilySettingsRequest{
		Enabled:                    &originalSettings.Enabled,
		MaxFamilyMembers:           maxMembersOrNil(originalSettings.MaxFamilyMembers),
		AllowMultipleFamiliesUsers: &originalSettings.AllowMultipleFamiliesUsers,
	})
	tryStep("Family().ConfigureSettings (restore original)", err)
}

// userFamilies returns the user's family memberships, or nil when the user is nil (a failed call).
func userFamilies(user *descope.UserResponse) []*descope.UserFamily {
	if user == nil {
		return nil
	}
	return user.UserFamilies
}

// maxMembersOrNil skips restoring an unset (zero) member limit, since the API requires it to be at least 1.
func maxMembersOrNil(maxMembers int32) *int32 {
	if maxMembers < 1 {
		return nil
	}
	return &maxMembers
}

// printSessionClaims prints the identity claims of a session JWT: the subject, the acting user (set
// while impersonating) and the selected family. The token itself is a live session credential, so it
// is never printed. The payload is decoded without verifying the signature, which is fine for display
// only - validate tokens with the SDK before trusting them.
func printSessionClaims(jwt string) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		fmt.Fprintln(os.Stderr, "  unexpected JWT format")
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "  failed to decode JWT payload: %v\n", err)
		return
	}
	var claims struct {
		Sub string         `json:"sub"`
		Act map[string]any `json:"act,omitempty"`
		Dcf string         `json:"dcf,omitempty"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		fmt.Fprintf(os.Stderr, "  failed to parse JWT claims: %v\n", err)
		return
	}
	if b, err := json.MarshalIndent(claims, "  ", "  "); err == nil {
		fmt.Println("  " + string(b))
	}
}
