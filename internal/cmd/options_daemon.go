// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/carabiner-labs/edera-attester/internal/attester"
)

const (
	flagIDDaemon   = "daemon"
	flagIDInsecure = "insecure"
)

// daemonOptions configures how the attester reaches the Edera Protect
// daemon.
type daemonOptions struct {
	config   *command.OptionsSetConfig
	Target   string
	Insecure bool
}

var _ command.OptionsSet = &daemonOptions{}

// Config returns the flag configuration for the daemon options.
func (do *daemonOptions) Config() *command.OptionsSetConfig {
	if do.config == nil {
		do.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				flagIDDaemon: {
					Long: "daemon",
					Help: "address of the Edera Protect daemon (defaults to the local unix socket)",
				},
				flagIDInsecure: {
					Long: "insecure",
					Help: "dial the daemon without TLS (implied for unix:// sockets)",
				},
			},
		}
	}
	return do.config
}

// AddFlags registers the daemon options on cmd.
func (do *daemonOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&do.Target,
		do.Config().LongFlag(flagIDDaemon),
		attester.DefaultSocket,
		do.Config().HelpText(flagIDDaemon),
	)
	cmd.PersistentFlags().BoolVar(
		&do.Insecure,
		do.Config().LongFlag(flagIDInsecure),
		false,
		do.Config().HelpText(flagIDInsecure),
	)
}

// Validate is a no-op for daemonOptions; connection errors surface at
// dial time.
func (do *daemonOptions) Validate() error {
	return nil
}
