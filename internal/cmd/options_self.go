// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

const flagIDSelf = "self"

// selfOptions toggles the self-attestation mode in which the workload
// id is derived from the machine hostname.
type selfOptions struct {
	config *command.OptionsSetConfig
	Self   bool
}

var _ command.OptionsSet = &selfOptions{}

// Config returns the flag configuration for the self-attest option.
func (so *selfOptions) Config() *command.OptionsSetConfig {
	if so.config == nil {
		so.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				flagIDSelf: {
					Long: "self",
					Help: "attest the current workload by reading its id from the machine hostname",
				},
			},
		}
	}
	return so.config
}

// AddFlags registers the self-attest flag on cmd.
func (so *selfOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(
		&so.Self,
		so.Config().LongFlag(flagIDSelf),
		false,
		so.Config().HelpText(flagIDSelf),
	)
}

// Validate is a no-op for selfOptions.
func (so *selfOptions) Validate() error {
	return nil
}

// hostnameAsID reads the workload id from the kernel hostname. The
// hostname of an Edera Protect workload is set to the workload's UUID.
func hostnameAsID() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("reading hostname: %w", err)
	}
	if host == "" {
		return "", fmt.Errorf("empty hostname")
	}
	return host, nil
}
