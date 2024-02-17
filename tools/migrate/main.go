package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/spf13/cobra"
)

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

// Command line flags

var Flags struct {
	Users   string
	Hashes  string
	Batch   int
	Dryrun  bool
	Json    bool
	Verbose bool
}

// Command line setup

var cli = &cobra.Command{
	Version:           "0.9.0",
	Use:               "migrate",
	Short:             "A command line utility for migrating users to Descope",
	Example:           "  # executes a dry run to test how an import of this data will behave\n  migrate import-users acmecorp --hashes pwhashes.txt --dryrun --verbose",
	CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
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
				fmt.Fprintln(os.Stderr, err)
			}
		},
	}
	setup(cmd)
	cmd.DisableFlagsInUseLine = true
	cmd.InitDefaultHelpFlag()
	cmd.Flags().Lookup("help").Hidden = true
	cmd.Flags().SortFlags = false
	cli.AddCommand(cmd)
}

func main() {
	addCommand(ImportUsers, "import-users <source> [--users <path>] [--hashes <path>] [--dryrun]", "Import users to a Descope project", func(cmd *cobra.Command) {
		cmd.Args = cobra.MaximumNArgs(1)
		cmd.Flags().StringVar(&Flags.Users, "users", "", "The path to the users data file (optional)")
		cmd.Flags().StringVar(&Flags.Hashes, "hashes", "", "The path to the hashes data file (optional)")
		cmd.Flags().IntVar(&Flags.Batch, "batch", 50, "The number of users to import in every batch server call")
		cmd.Flags().BoolVar(&Flags.Dryrun, "dryrun", false, "Performs a dry run that only validates the imported data")
		cmd.Flags().BoolVar(&Flags.Verbose, "verbose", false, "Prints all import results and not just failures")
		cmd.Flags().BoolVar(&Flags.Json, "json", false, "Disables progress messages and outputs the results in JSON format")
		cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("the source argument is required")
			}
			if Flags.Batch < 2 || Flags.Batch > 50 {
				return errors.New("batch size must be between 2 and 50")
			}
			if Flags.Users == "" && Flags.Hashes == "" {
				return errors.New("at least one data file is required")
			}
			return nil
		}
	})

	cli.SetHelpCommand(&cobra.Command{Hidden: true})

	err := cli.Execute()
	if err != nil {
		os.Exit(1)
	}
}
