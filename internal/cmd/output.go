// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// writeStatement marshals statement as indented JSON and writes it to w
// followed by a trailing newline.
func writeStatement(w io.Writer, statement *intoto.Statement) error {
	marshaler := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   false,
	}
	data, err := marshaler.Marshal(statement)
	if err != nil {
		return fmt.Errorf("marshaling statement: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing statement: %w", err)
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return fmt.Errorf("writing trailing newline: %w", err)
	}
	return nil
}
