// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const flagIDSpiffeSubject = "spiffe-subject"

// spiffeOptions holds the optional SPIFFE SVID URI that gets attached
// to the attestation as an additional in-toto subject.
type spiffeOptions struct {
	config  *command.OptionsSetConfig
	Subject string
}

var _ command.OptionsSet = &spiffeOptions{}

// Config returns the flag configuration for the spiffe options.
func (so *spiffeOptions) Config() *command.OptionsSetConfig {
	if so.config == nil {
		so.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				flagIDSpiffeSubject: {
					Long: "spiffe-subject",
					Help: "attach a SPIFFE SVID URI as an additional subject of the attestation",
				},
			},
		}
	}
	return so.config
}

// AddFlags registers the --spiffe-subject flag on cmd.
func (so *spiffeOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&so.Subject,
		so.Config().LongFlag(flagIDSpiffeSubject),
		"",
		so.Config().HelpText(flagIDSpiffeSubject),
	)
}

// Validate ensures the configured value parses as a SPIFFE ID.
func (so *spiffeOptions) Validate() error {
	if so.Subject == "" {
		return nil
	}
	if _, err := spiffeid.FromString(so.Subject); err != nil {
		return fmt.Errorf("invalid SPIFFE SVID URI %q: %w", so.Subject, err)
	}
	return nil
}
