// Package podresources reads the pinned kubelet v1 API, without changing state.
package podresources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"

	"google.golang.org/protobuf/proto"
	v1 "k8s.io/kubelet/pkg/apis/podresources/v1"
)

var uuid = regexp.MustCompile(`^GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type Allocation struct {
	DeviceID  string `json:"device_id"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
}
type Inventory struct {
	Schema         string                           `json:"schema"`
	Complete       bool                             `json:"complete"`
	DeviceIDs      []string                         `json:"device_ids"`
	Allocations    []Allocation                     `json:"allocations"`
	List           *v1.ListPodResourcesResponse     `json:"raw_list"`
	Allocatable    *v1.AllocatableResourcesResponse `json:"raw_allocatable"`
	ListSHA        string                           `json:"list_proto_sha256"`
	AllocatableSHA string                           `json:"allocatable_proto_sha256"`
}

func hash(message proto.Message) string {
	raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func Snapshot(ctx context.Context, client v1.PodResourcesListerClient) (*Inventory, error) {
	before, err := client.List(ctx, &v1.ListPodResourcesRequest{})
	if err != nil {
		return nil, err
	}
	all, err := client.GetAllocatableResources(ctx, &v1.AllocatableResourcesRequest{})
	if err != nil {
		return nil, err
	}
	after, err := client.List(ctx, &v1.ListPodResourcesRequest{})
	if err != nil {
		return nil, err
	}
	if before == nil || all == nil || after == nil || !proto.Equal(before, after) {
		return nil, errors.New("podresources:incomplete_or_changed")
	}
	out := &Inventory{Schema: "inf037b-podresources-v1", Complete: true, DeviceIDs: []string{}, Allocations: []Allocation{}, List: before, Allocatable: all, ListSHA: hash(before), AllocatableSHA: hash(all)}
	known := map[string]bool{}
	for _, group := range all.Devices {
		if group.ResourceName != "nvidia.com/gpu" {
			if regexp.MustCompile(`(?i)nvidia|gpu|mig`).MatchString(group.ResourceName) {
				return nil, errors.New("podresources:unsupported_resource")
			}
			continue
		}
		for _, id := range group.DeviceIds {
			if !uuid.MatchString(id) || known[id] {
				return nil, errors.New("podresources:device_id")
			}
			known[id] = true
			out.DeviceIDs = append(out.DeviceIDs, id)
		}
	}
	if len(known) == 0 {
		return nil, errors.New("podresources:device_inventory_unknown")
	}
	used := map[string]bool{}
	for _, pod := range before.PodResources {
		for _, container := range pod.Containers {
			if len(container.DynamicResources) != 0 {
				return nil, errors.New("podresources:dynamic_unknown")
			}
			for _, group := range container.Devices {
				if group.ResourceName != "nvidia.com/gpu" {
					if regexp.MustCompile(`(?i)nvidia|gpu|mig`).MatchString(group.ResourceName) {
						return nil, errors.New("podresources:unsupported_resource")
					}
					continue
				}
				for _, id := range group.DeviceIds {
					if !uuid.MatchString(id) || !known[id] || used[id] || pod.Name == "" || pod.Namespace == "" || container.Name == "" {
						return nil, errors.New("podresources:allocation_or_sharing")
					}
					used[id] = true
					out.Allocations = append(out.Allocations, Allocation{id, pod.Namespace, pod.Name, container.Name})
				}
			}
		}
	}
	sort.Strings(out.DeviceIDs)
	sort.Slice(out.Allocations, func(i, j int) bool { return out.Allocations[i].DeviceID < out.Allocations[j].DeviceID })
	return out, nil
}
