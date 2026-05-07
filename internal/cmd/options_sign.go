// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/carabiner-dev/signer/options"
	"github.com/spf13/cobra"
)

// spiffeBackend is the --signing-backend value selected when a SPIFFE
// socket is configured (matches options.BackendSpiffe).
const spiffeBackend = "spiffe"

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
	so.applySpiffeAutoDetect()
	if !so.Sign {
		return nil
	}
	return so.SignerSet.Validate()
}

// applySpiffeAutoDetect turns signing on and selects the SPIFFE backend
// when a Workload API socket is configured via --spiffe-socket or the
// SPIFFE_ENDPOINT_SOCKET environment variable. The signer's own
// auto-detection only inspects the explicit flag, so this wrapper
// handles the env-var fallback for containerized invocations.
func (so *signOptions) applySpiffeAutoDetect() {
	if so.SignerSet == nil || so.SignerSet.Spiffe == nil || so.SignerSet.Spiffe.Sign == nil {
		return
	}
	if so.SignerSet.Spiffe.Sign.EffectiveSocketPath() == "" {
		return
	}
	so.Sign = true
	if so.SignerSet.Backend == "" {
		so.SignerSet.Backend = spiffeBackend
	}
}
