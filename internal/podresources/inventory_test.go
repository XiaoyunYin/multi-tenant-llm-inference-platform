package podresources

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	v1 "k8s.io/kubelet/pkg/apis/podresources/v1"
)

const gpu = "GPU-00000000-0000-0000-0000-000000000001"

type server struct {
	v1.UnimplementedPodResourcesListerServer
	id               string
	shared, changing bool
	calls            int
}

func (s *server) List(context.Context, *v1.ListPodResourcesRequest) (*v1.ListPodResourcesResponse, error) {
	s.calls++
	id := s.id
	if s.changing && s.calls > 1 {
		id = gpu + "::0"
	}
	ids := []string{id}
	if s.shared {
		ids = append(ids, id)
	}
	return &v1.ListPodResourcesResponse{PodResources: []*v1.PodResources{{Name: "engine", Namespace: "unit", Containers: []*v1.ContainerResources{{Name: "model", Devices: []*v1.ContainerDevices{{ResourceName: "nvidia.com/gpu", DeviceIds: ids}}}}}}}, nil
}
func (s *server) GetAllocatableResources(context.Context, *v1.AllocatableResourcesRequest) (*v1.AllocatableResourcesResponse, error) {
	return &v1.AllocatableResourcesResponse{Devices: []*v1.ContainerDevices{{ResourceName: "nvidia.com/gpu", DeviceIds: []string{s.id}}}}, nil
}
func check(t *testing.T, network, address string, s *server, wantErr bool) {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	service := grpc.NewServer()
	v1.RegisterPodResourcesListerServer(service, s)
	go service.Serve(listener)
	t.Cleanup(service.Stop)
	conn, err := grpc.NewClient("passthrough:///test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	result, err := Snapshot(ctx, v1.NewPodResourcesListerClient(conn))
	if wantErr {
		if err == nil {
			t.Fatal("invalid inventory accepted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.DeviceIDs) != 1 || len(result.Allocations) != 1 || result.Allocations[0].Pod != "engine" || len(result.ListSHA) != 64 {
		t.Fatalf("incomplete result: %+v", result)
	}
}
func TestTCP(t *testing.T) { check(t, "tcp", "127.0.0.1:0", &server{id: gpu}, false) }
func TestRefusals(t *testing.T) {
	for _, s := range []*server{{id: gpu + "::0"}, {id: "MIG-123"}, {id: gpu, shared: true}, {id: gpu, changing: true}} {
		check(t, "tcp", "127.0.0.1:0", s, true)
	}
}
func TestUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux Unix-socket case is required by the CPU-host manifest")
	}
	check(t, "unix", filepath.Join(t.TempDir(), "kubelet.sock"), &server{id: gpu}, false)
}
