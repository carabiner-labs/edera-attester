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

type workloadOptions struct {
	daemon     daemonOptions
	self       selfOptions
	sign       signOptions
	spiffe     spiffeOptions
	out        output.Options
	WorkloadID string
	argID      string // raw positional arg, before --self resolution
}

func (wo *workloadOptions) AddFlags(cmd *cobra.Command) {
	wo.daemon.AddFlags(cmd)
	wo.self.AddFlags(cmd)
	wo.sign.AddFlags(cmd)
	wo.spiffe.AddFlags(cmd)
	wo.out.AddFlags(cmd)
}

func (wo *workloadOptions) Validate() error {
	errs := []error{
		wo.daemon.Validate(),
		wo.self.Validate(),
		wo.sign.Validate(),
		wo.spiffe.Validate(),
		wo.out.Validate(),
	}
	switch {
	case wo.self.Self && wo.argID != "":
		errs = append(errs, errors.New("--self cannot be combined with a workload id argument"))
	case !wo.self.Self && wo.WorkloadID == "":
		errs = append(errs, errors.New("a workload id argument or --self is required"))
	}
	return errors.Join(errs...)
}

func addWorkload(parent *cobra.Command) {
	opts := &workloadOptions{
		sign: defaultSignOptions(),
	}
	cmd := &cobra.Command{
		Short: "produce an in-toto attestation for an Edera Protect workload",
		Long: `Produce an in-toto attestation describing an Edera Protect workload, ` +
			`including the OCI image it runs and the zone hosting it. ` +
			`When --self is set the workload id is read from the machine hostname, ` +
			`which lets a workload attest itself when it runs inside an Edera zone.`,
		Use: "workload [flags] [WORKLOAD_ID]",
		Example: fmt.Sprintf(`  %s workload e601d3e3-cf51-48af-b7ac-54ed9798cadd
  %s workload --self`, appname, appname),
		SilenceUsage:  false,
		SilenceErrors: true,
		Args:          cobra.MaximumNArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.argID = args[0]
				opts.WorkloadID = args[0]
			}
			if opts.self.Self && opts.WorkloadID == "" {
				id, err := hostnameAsID()
				if err != nil {
					return err
				}
				opts.WorkloadID = id
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

			statement, err := a.AttestWorkload(ctx, opts.WorkloadID, opts.spiffe.Subject)
			if err != nil {
				return fmt.Errorf("building workload attestation: %w", err)
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
