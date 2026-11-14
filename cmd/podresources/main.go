// podresources is a read-only, deadline-bound kubelet PodResources client.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	v1 "k8s.io/kubelet/pkg/apis/podresources/v1"

	"multi-tenant-llm-inference-platform/internal/podresources"
)

func main() {
	socket := flag.String("socket", "/var/lib/kubelet/pod-resources/kubelet.sock", "read-only kubelet socket")
	flag.Parse()
	client, err := grpc.NewClient("passthrough:///podresources", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
	}), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4<<20)))
	if err == nil {
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var result *podresources.Inventory
		result, err = podresources.Snapshot(ctx, v1.NewPodResourcesListerClient(client))
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(result)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
