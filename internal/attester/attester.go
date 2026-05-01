// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package attester drives the Edera Protect daemon, collects zone and
// workload state, and shapes it into in-toto v1 statements with the
// predicate types defined in the predicate package.
package attester

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/carabiner-labs/protect/client"
	controlv1 "github.com/carabiner-labs/protect/gen/protect/control/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/carabiner-labs/edera-attester/internal/predicate"
)

// DefaultSocket is the local Edera Protect daemon unix socket.
const DefaultSocket = "unix:///var/lib/edera/protect/daemon.socket"

// Attester wraps a connected Edera Protect ControlService client and
// produces in-toto statements for zones and workloads.
type Attester struct {
	client *client.Client
}

// New connects to the daemon at target and returns a ready Attester.
// Pass an empty target to use DefaultSocket.
func New(ctx context.Context, target string, insecureConn bool) (*Attester, error) {
	if target == "" {
		target = DefaultSocket
	}
	opts := []client.Option{}
	if insecureConn || strings.HasPrefix(target, "unix://") {
		opts = append(opts, client.WithInsecure())
	}
	c, err := client.Dial(ctx, target, opts...)
	if err != nil {
		return nil, fmt.Errorf("dialing protect daemon: %w", err)
	}
	return &Attester{client: c}, nil
}

// Close releases the underlying gRPC connection.
func (a *Attester) Close() error {
	if a == nil || a.client == nil {
		return nil
	}
	return a.client.Close()
}

// HostStatus returns the daemon's host status.
func (a *Attester) HostStatus(ctx context.Context) (*controlv1.GetHostStatusReply, error) {
	reply, err := a.client.Control.GetHostStatus(ctx, &controlv1.GetHostStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("calling GetHostStatus: %w", err)
	}
	return reply, nil
}

// ListZones streams all zones known to the daemon.
func (a *Attester) ListZones(ctx context.Context) ([]*controlv1.Zone, error) {
	stream, err := a.client.Control.ListZones(ctx, &controlv1.ListZonesRequest{})
	if err != nil {
		return nil, fmt.Errorf("calling ListZones: %w", err)
	}
	var zones []*controlv1.Zone
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("receiving from ListZones stream: %w", err)
		}
		zones = append(zones, msg.GetZones()...)
	}
	return zones, nil
}

// ListWorkloads streams all workloads known to the daemon.
func (a *Attester) ListWorkloads(ctx context.Context) ([]*controlv1.Workload, error) {
	stream, err := a.client.Control.ListWorkloads(ctx, &controlv1.ListWorkloadsRequest{})
	if err != nil {
		return nil, fmt.Errorf("calling ListWorkloads: %w", err)
	}
	var workloads []*controlv1.Workload
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("receiving from ListWorkloads stream: %w", err)
		}
		workloads = append(workloads, msg.GetWorkloads()...)
	}
	return workloads, nil
}

// ListImages streams all OCI images known to the daemon.
func (a *Attester) ListImages(ctx context.Context) ([]*controlv1.OciImageInfo, error) {
	stream, err := a.client.Control.ListImages(ctx, &controlv1.ListImagesRequest{})
	if err != nil {
		return nil, fmt.Errorf("calling ListImages: %w", err)
	}
	var images []*controlv1.OciImageInfo
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("receiving from ListImages stream: %w", err)
		}
		images = append(images, msg.GetImages()...)
	}
	return images, nil
}

// FindZone returns the zone with the given id, or an error if not found.
func (a *Attester) FindZone(ctx context.Context, id string) (*controlv1.Zone, error) {
	zones, err := a.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	for _, z := range zones {
		if z.GetId() == id {
			return z, nil
		}
	}
	return nil, fmt.Errorf("zone %q not found", id)
}

// FindWorkload returns the workload with the given id, or an error if
// not found.
func (a *Attester) FindWorkload(ctx context.Context, id string) (*controlv1.Workload, error) {
	workloads, err := a.ListWorkloads(ctx)
	if err != nil {
		return nil, err
	}
	for _, w := range workloads {
		if w.GetId() == id {
			return w, nil
		}
	}
	return nil, fmt.Errorf("workload %q not found", id)
}

// FindImage returns the image with the given digest, if the daemon
// knows about it. The lookup is best-effort: if the image is not
// reported by the daemon, FindImage returns nil with no error.
func (a *Attester) FindImage(ctx context.Context, digest string) (*controlv1.OciImageInfo, error) {
	if digest == "" {
		return nil, nil
	}
	images, err := a.ListImages(ctx)
	if err != nil {
		return nil, err
	}
	for _, img := range images {
		if img.GetDigest() == digest {
			return img, nil
		}
	}
	return nil, nil
}

// AttestZone builds an in-toto v1 statement attesting the given zone.
func (a *Attester) AttestZone(ctx context.Context, zoneID string) (*intoto.Statement, error) {
	host, err := a.HostStatus(ctx)
	if err != nil {
		return nil, err
	}
	zone, err := a.FindZone(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	pred := &predicate.Zone{
		Host: hostFromReply(host),
		Zone: zoneInfoFromProto(zone),
	}
	predStruct, err := toStruct(pred)
	if err != nil {
		return nil, fmt.Errorf("encoding zone predicate: %w", err)
	}

	return &intoto.Statement{
		Type:          intoto.StatementTypeUri,
		Subject:       []*intoto.ResourceDescriptor{zoneSubject(zone)},
		PredicateType: predicate.TypeZone,
		Predicate:     predStruct,
	}, nil
}

// AttestWorkload builds an in-toto v1 statement attesting the given
// workload, including its zone context and OCI image metadata.
func (a *Attester) AttestWorkload(ctx context.Context, workloadID string) (*intoto.Statement, error) {
	host, err := a.HostStatus(ctx)
	if err != nil {
		return nil, err
	}
	workload, err := a.FindWorkload(ctx, workloadID)
	if err != nil {
		return nil, err
	}

	pred := &predicate.Workload{
		Host:     hostFromReply(host),
		Workload: workloadInfoFromProto(workload),
	}

	if zoneID := workload.GetSpec().GetZoneId(); zoneID != "" {
		zone, err := a.FindZone(ctx, zoneID)
		if err == nil {
			pred.Zone = zoneInfoFromProto(zone)
		}
	}

	imageDigest := workload.GetSpec().GetImage().GetDigest()
	imageInfo, err := a.FindImage(ctx, imageDigest)
	if err != nil {
		return nil, err
	}
	pred.Image = imageFromInfo(imageInfo, workload.GetSpec().GetImage())

	predStruct, err := toStruct(pred)
	if err != nil {
		return nil, fmt.Errorf("encoding workload predicate: %w", err)
	}

	return &intoto.Statement{
		Type:          intoto.StatementTypeUri,
		Subject:       workloadSubjects(workload),
		PredicateType: predicate.TypeWorkload,
		Predicate:     predStruct,
	}, nil
}

// hostFromReply maps the daemon host status reply to the predicate type.
func hostFromReply(r *controlv1.GetHostStatusReply) *predicate.Host {
	if r == nil {
		return nil
	}
	return &predicate.Host{
		UUID:           r.GetHostUuid(),
		ProtectVersion: r.GetProtectVersion(),
		ProtectGitSHA:  r.GetProtectGitSha(),
		ProtectLastTag: r.GetProtectLastTag(),
		ProtectBranch:  r.GetProtectBranch(),
		IPv4:           r.GetHostIpv4(),
		IPv6:           r.GetHostIpv6(),
		MAC:            r.GetHostMac(),
	}
}

// zoneInfoFromProto converts a Zone proto to the public predicate view.
func zoneInfoFromProto(z *controlv1.Zone) *predicate.ZoneInfo {
	if z == nil {
		return nil
	}
	spec := z.GetSpec()
	status := z.GetStatus()

	out := &predicate.ZoneInfo{
		ID:          z.GetId(),
		Name:        spec.GetName(),
		State:       status.GetState().String(),
		Host:        status.GetHost(),
		DomID:       status.GetDomid(),
		CreatedAt:   timeFromTs(status.GetCreatedAt().GetSeconds(), status.GetCreatedAt().GetNanos()),
		ReadyAt:     timeFromTs(status.GetReadyAt().GetSeconds(), status.GetReadyAt().GetNanos()),
		Kernel:      imageFromSpec(spec.GetKernel()),
		Initrd:      imageFromSpec(spec.GetInitrd()),
		Annotations: annotationsToMap(spec.GetAnnotations()),
	}

	for _, addon := range spec.GetAddons() {
		out.Addons = append(out.Addons, imageFromSpec(addon))
	}

	if r := status.GetResourceStatus().GetActiveResources(); r != nil {
		out.Resources = &predicate.ZoneResources{
			MaxMemory:        r.GetMaxMemory(),
			MinMemory:        r.GetMinMemory(),
			TargetMemory:     r.GetTargetMemory(),
			MaxCPUs:          r.GetMaxCpus(),
			MinCPUs:          r.GetMinCpus(),
			TargetCPUs:       r.GetTargetCpus(),
			AdjustmentPolicy: r.GetAdjustmentPolicy().String(),
		}
	}

	if net := status.GetNetworkStatus(); net != nil {
		out.Network = networkFromStatus(net)
	}

	return out
}

// networkFromStatus extracts the public-facing network information from
// the zone's network status.
func networkFromStatus(net *controlv1.ZoneNetworkStatus) *predicate.ZoneNetwork {
	zn := &predicate.ZoneNetwork{}
	for _, iface := range net.GetInterfaces() {
		entry := &predicate.ZoneNetworkInterface{
			HostInterface: iface.GetHostInterface(),
			ZoneInterface: iface.GetZoneInterface(),
			MAC:           iface.GetZoneMac(),
		}
		for _, ip := range iface.GetIps() {
			switch ip.GetVersion() {
			case controlv1.ZoneNetworkIpVersion_ZONE_NETWORK_IP_VERSION_V4:
				entry.IPv4 = ip.GetAddress()
				entry.IPv4Gateway = ip.GetGateway()
			case controlv1.ZoneNetworkIpVersion_ZONE_NETWORK_IP_VERSION_V6:
				entry.IPv6 = ip.GetAddress()
				entry.IPv6Gateway = ip.GetGateway()
			case controlv1.ZoneNetworkIpVersion_ZONE_NETWORK_IP_VERSION_UNKNOWN:
				// nothing to record for an unspecified IP version.
			}
		}
		zn.Interfaces = append(zn.Interfaces, entry)
	}
	return zn
}

// workloadInfoFromProto converts a Workload proto to the public view.
func workloadInfoFromProto(w *controlv1.Workload) *predicate.WorkloadInfo {
	if w == nil {
		return nil
	}
	spec := w.GetSpec()
	status := w.GetStatus()
	return &predicate.WorkloadInfo{
		ID:          w.GetId(),
		Name:        spec.GetName(),
		State:       status.GetState().String(),
		ZoneID:      spec.GetZoneId(),
		Hostname:    spec.GetHostname(),
		Command:     spec.GetProcess().GetCommand(),
		CreatedAt:   timeFromTs(status.GetCreatedAt().GetSeconds(), status.GetCreatedAt().GetNanos()),
		Annotations: annotationsToMap(spec.GetAnnotations()),
	}
}

// imageFromSpec turns an OciImageSpec reference into the predicate view.
func imageFromSpec(s *controlv1.OciImageSpec) *predicate.Image {
	if s == nil {
		return nil
	}
	return &predicate.Image{
		Digest: s.GetDigest(),
		Format: s.GetFormat().String(),
	}
}

// imageFromInfo merges the image spec referenced by a workload with the
// richer metadata returned by ListImages, when available.
func imageFromInfo(info *controlv1.OciImageInfo, spec *controlv1.OciImageSpec) *predicate.Image {
	out := imageFromSpec(spec)
	if info == nil {
		return out
	}
	if out == nil {
		out = &predicate.Image{
			Digest: info.GetDigest(),
			Format: info.GetFormat().String(),
		}
	}
	out.Names = info.GetNames()
	if md := info.GetMetadata(); md != nil {
		out.Manifest = string(md.GetManifest())
		out.Config = string(md.GetConfig())
	}
	return out
}

// annotationsToMap flattens a list of AnnotationSpec into a map.
func annotationsToMap(annotations []*controlv1.AnnotationSpec) map[string]string {
	if len(annotations) == 0 {
		return nil
	}
	out := make(map[string]string, len(annotations))
	for _, a := range annotations {
		out[a.GetKey()] = a.GetValue()
	}
	return out
}

// timeFromTs converts a protobuf timestamp pair into a *time.Time. It
// returns nil for a zero timestamp so that omitempty triggers on the
// JSON output.
func timeFromTs(seconds int64, nanos int32) *time.Time {
	if seconds == 0 && nanos == 0 {
		return nil
	}
	t := time.Unix(seconds, int64(nanos)).UTC()
	return &t
}

// zoneSubject builds the in-toto subject for a zone attestation.
func zoneSubject(z *controlv1.Zone) *intoto.ResourceDescriptor {
	id := z.GetId()
	return &intoto.ResourceDescriptor{
		Name:   "edera-zone:" + id,
		Digest: map[string]string{"sha256": sha256Hex(id)},
	}
}

// workloadSubjects returns the in-toto subjects for a workload
// attestation: the workload itself plus its OCI image (when available).
func workloadSubjects(w *controlv1.Workload) []*intoto.ResourceDescriptor {
	id := w.GetId()
	subjects := []*intoto.ResourceDescriptor{
		{
			Name:   "edera-workload:" + id,
			Digest: map[string]string{"sha256": sha256Hex(id)},
		},
	}
	return subjects
}

// sha256Hex returns the lowercase hex sha256 of s.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// toStruct converts an arbitrary Go value into a protobuf Struct via
// JSON, which is what intoto.Statement.Predicate expects.
func toStruct(v any) (*structpb.Struct, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate: %w", err)
	}
	s := &structpb.Struct{}
	if err := protojson.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("decoding into struct: %w", err)
	}
	return s, nil
}
