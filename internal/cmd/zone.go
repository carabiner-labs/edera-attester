// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/command/output"
	"github.com/carabiner-dev/signer"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/carabiner-labs/edera-attester/internal/attester"
)

type zoneOptions struct {
	daemon daemonOptions
	sign   signOptions
	out    output.Options
	ZoneID string
}

func (zo *zoneOptions) AddFlags(cmd *cobra.Command) {
	zo.daemon.AddFlags(cmd)
	zo.sign.AddFlags(cmd)
	zo.out.AddFlags(cmd)
}

func (zo *zoneOptions) Validate() error {
	errs := []error{
		zo.daemon.Validate(),
		zo.sign.Validate(),
		zo.out.Validate(),
	}
	if zo.ZoneID == "" {
		errs = append(errs, errors.New("zone id is required"))
	}
	return errors.Join(errs...)
}

func addZone(parent *cobra.Command) {
	opts := &zoneOptions{
		sign: defaultSignOptions(),
	}
	cmd := &cobra.Command{
		Short:         "produce an in-toto attestation for an Edera Protect zone",
		Long:          "Produce an in-toto attestation describing the state of an Edera Protect zone as reported by the daemon.",
		Use:           "zone [flags] ZONE_ID",
		Example:       fmt.Sprintf("%s zone a307513d-70d3-4b74-aed8-f07a0db83f58", appname),
		SilenceUsage:  false,
		SilenceErrors: true,
		Args:          cobra.MaximumNArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.ZoneID = args[0]
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validating options: %w", err)
			}

			ctx := cmd.Context()
			a, err := attester.New(ctx, opts.daemon.Target, opts.daemon.Insecure)
			if err != nil {
				return err
			}
			defer func() {
				if err := a.Close(); err != nil {
					logrus.Warnf("closing daemon connection: %v", err)
				}
			}()

			statement, err := a.AttestZone(ctx, opts.ZoneID)
			if err != nil {
				return fmt.Errorf("building zone attestation: %w", err)
			}

			w, err := opts.out.GetWriter()
			if err != nil {
				return fmt.Errorf("opening output: %w", err)
			}

			if opts.sign.Sign {
				s, err := signer.NewSignerFromSet(opts.sign.SignerSet)
				if err != nil {
					return fmt.Errorf("building signer: %w", err)
				}
				defer func() {
					if err := s.Close(); err != nil {
						logrus.Warnf("closing signer: %v", err)
					}
				}()
				return signAndWriteStatement(w, statement, s)
			}
			return writeStatement(w, statement)
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
