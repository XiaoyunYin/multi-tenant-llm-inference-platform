package diagnostics

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestProfilerIsExplicitLoopbackOnly(t *testing.T) {
	for _, address := range []string{"0.0.0.0:6060", ":6060", "localhost:6060", "192.0.2.1:6060", "127.0.0.1:-1", "[::]:6060"} {
		if ValidateAddress(address) == nil {
			t.Fatalf("accepted non-literal-loopback address %q", address)
		}
	}
	server, listener, err := Start("")
	if err != nil || server != nil || listener != nil {
		t.Fatal("default starts a profiler")
	}
	server, listener, err = Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	response, err := http.Get("http://" + listener.Addr().String() + "/debug/pprof/heap?debug=1")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || !strings.Contains(string(body), "heap profile:") {
		t.Fatalf("heap endpoint: %d %v", response.StatusCode, err)
	}
}
