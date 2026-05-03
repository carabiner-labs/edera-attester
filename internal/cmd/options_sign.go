// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/carabiner-dev/signer/options"
	"github.com/spf13/cobra"
)

const flagIDSign = "sign"

// signOptions bundles the --sign toggle with the full signer configuration
// surface from github.com/carabiner-dev/signer. When Sign is false the
// signer flags are still registered (so --help is complete) but Validate
// and BuildSigner are skipped.
type signOptions struct {
	Sign      bool
	SignerSet *options.SignerSet
}

func defaultSignOptions() signOptions {
	return signOptions{
		SignerSet: options.DefaultSignerSet(),
	}
}

func (so *signOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(
		&so.Sign, flagIDSign, false,
		"sign the attestation using the configured signing backend",
	)
	so.SignerSet.AddFlags(cmd)
}

func (so *signOptions) Validate() error {
	if !so.Sign {
		return nil
	}
	return so.SignerSet.Validate()
}
