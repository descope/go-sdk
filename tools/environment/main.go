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

func prepare(projectID string) (err error) {
	descopeConfig := &client.Config{
		ProjectID:      projectID,
		ManagementKey:  os.Getenv(descope.EnvironmentVariableManagementKey),
		DescopeBaseURL: os.Getenv(descope.EnvironmentVariableBaseURL),
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
	Path   string
	Format string
	Debug  bool
}

// Command line setup

var cli = &cobra.Command{
	Version:           "0.9.0",
	Use:               "environment",
	Short:             "A command line utility for managing Descope project environments",
	CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return prepare(args[0])
		}
		return nil
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
	cmd.InitDefaultHelpFlag()
	cmd.Flags().Lookup("help").Hidden = true
	cmd.Flags().SortFlags = false
	cli.AddCommand(cmd)
}

func main() {
	addCommand(ExportProject, "export-project <ProjectID>", "Export all configuration from a project", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.Flags().StringVar(&Flags.Path, "path", "", "The path to export the project into")
		cmd.Flags().StringVar(&Flags.Format, "format", "split", "The export format: 'split' (default) or 'whole'")
		cmd.Flags().BoolVar(&Flags.Debug, "debug", false, "Saves an export.log trace file in the debug directory")
	})

	addCommand(ImportProject, "import-project <ProjectID>", "Import all configuration into a project", func(cmd *cobra.Command) {
		cmd.Args = cobra.ExactArgs(1)
		cmd.Flags().StringVar(&Flags.Path, "path", "", "The path to import the project from")
		cmd.Flags().BoolVar(&Flags.Debug, "debug", false, "Saves an import.log trace file in the debug directory")
	})

	cli.SetHelpCommand(&cobra.Command{Hidden: true})

	err := cli.Execute()
	if err != nil {
		os.Exit(1)
	}
}
