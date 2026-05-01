// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package cmd implements the edera-attester CLI.
package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/log"
)

const appname = "edera-attester"

var rootCmd = &cobra.Command{
	Short: fmt.Sprintf("%s: produces in-toto attestations from an Edera Protect daemon", appname),
	Long: fmt.Sprintf(`
%s

Generates in-toto attestations describing Edera Protect zones and workloads
by talking to the Protect daemon (locally over its unix socket or remotely).

Two subcommands are available:

  %s zone     Attest a zone, capturing its host, kernel, network and resources.
  %s workload Attest a workload, including the OCI image it runs and its zone.

The workload command supports a --self mode that reads the workload id from
the machine hostname, so a workload running inside an Edera zone can attest
itself.
`, appname, appname, appname),
	Use:               appname,
	SilenceUsage:      false,
	PersistentPreRunE: initLogging,
}

type rootOptions struct {
	logLevel string
}

var rootOpts = rootOptions{}

func initLogging(*cobra.Command, []string) error {
	return log.SetupGlobalLogger(rootOpts.logLevel)
}

// Execute wires up the subcommands and runs the CLI.
func Execute() {
	rootCmd.PersistentFlags().StringVar(
		&rootOpts.logLevel,
		"log-level", "info", fmt.Sprintf("the logging verbosity, either %s", log.LevelNames()),
	)

	addZone(rootCmd)
	addWorkload(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}
