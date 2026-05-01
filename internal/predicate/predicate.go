// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package predicate defines the in-toto predicate shapes that the
// edera-attester emits to describe Edera Protect zones and workloads.
package predicate

import "time"

// Type identifiers for the predicates produced by the attester.
const (
	TypeZone     = "https://labs.carabiner.dev/edera/zone/v0.1"
	TypeWorkload = "https://labs.carabiner.dev/edera/workload/v0.1"
)

// Zone is the predicate emitted by `edera-attester zone`. It records the
// state of a zone as reported by the Edera Protect daemon together with
// host context.
type Zone struct {
	Host *Host     `json:"host,omitempty"`
	Zone *ZoneInfo `json:"zone"`
}

// Workload is the predicate emitted by `edera-attester workload`. It
// captures the workload's runtime state, the OCI image it runs, and
// information about the zone that hosts it.
type Workload struct {
	Host     *Host         `json:"host,omitempty"`
	Zone     *ZoneInfo     `json:"zone,omitempty"`
	Workload *WorkloadInfo `json:"workload"`
	Image    *Image        `json:"image,omitempty"`
}

// Host carries the Edera Protect daemon and host metadata.
type Host struct {
	UUID           string `json:"uuid,omitempty"`
	ProtectVersion string `json:"protectVersion,omitempty"`
	ProtectGitSHA  string `json:"protectGitSha,omitempty"`
	ProtectLastTag string `json:"protectLastTag,omitempty"`
	ProtectBranch  string `json:"protectBranch,omitempty"`
	IPv4           string `json:"ipv4,omitempty"`
	IPv6           string `json:"ipv6,omitempty"`
	MAC            string `json:"mac,omitempty"`
}

// ZoneInfo is the public view of an Edera Protect zone.
type ZoneInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name,omitempty"`
	State       string            `json:"state,omitempty"`
	Host        string            `json:"host,omitempty"`
	DomID       uint32            `json:"domid,omitempty"`
	CreatedAt   *time.Time        `json:"createdAt,omitempty"`
	ReadyAt     *time.Time        `json:"readyAt,omitempty"`
	Kernel      *Image            `json:"kernel,omitempty"`
	Initrd      *Image            `json:"initrd,omitempty"`
	Addons      []*Image          `json:"addons,omitempty"`
	Resources   *ZoneResources    `json:"resources,omitempty"`
	Network     *ZoneNetwork      `json:"network,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ZoneResources captures the active resource budget for a zone.
type ZoneResources struct {
	MaxMemory        uint64 `json:"maxMemory,omitempty"`
	MinMemory        uint64 `json:"minMemory,omitempty"`
	TargetMemory     uint64 `json:"targetMemory,omitempty"`
	MaxCPUs          uint32 `json:"maxCpus,omitempty"`
	MinCPUs          uint32 `json:"minCpus,omitempty"`
	TargetCPUs       uint32 `json:"targetCpus,omitempty"`
	AdjustmentPolicy string `json:"adjustmentPolicy,omitempty"`
}

// ZoneNetwork captures the network status reported for a zone.
type ZoneNetwork struct {
	Interfaces []*ZoneNetworkInterface `json:"interfaces,omitempty"`
}

// ZoneNetworkInterface describes one of a zone's network interfaces.
type ZoneNetworkInterface struct {
	HostInterface string `json:"hostInterface,omitempty"`
	ZoneInterface string `json:"zoneInterface,omitempty"`
	MAC           string `json:"mac,omitempty"`
	IPv4          string `json:"ipv4,omitempty"`
	IPv4Gateway   string `json:"ipv4Gateway,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	IPv6Gateway   string `json:"ipv6Gateway,omitempty"`
}

// WorkloadInfo describes an Edera Protect workload.
type WorkloadInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name,omitempty"`
	State       string            `json:"state,omitempty"`
	ZoneID      string            `json:"zoneId,omitempty"`
	Hostname    string            `json:"hostname,omitempty"`
	Command     []string          `json:"command,omitempty"`
	CreatedAt   *time.Time        `json:"createdAt,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Image describes an OCI image referenced by the daemon.
type Image struct {
	Digest   string   `json:"digest,omitempty"`
	Format   string   `json:"format,omitempty"`
	Names    []string `json:"names,omitempty"`
	Manifest string   `json:"manifest,omitempty"`
	Config   string   `json:"config,omitempty"`
}
