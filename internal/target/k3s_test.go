package target

import (
	"strings"
	"testing"
)

func TestParseRuntimeContainerID(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantRuntime string
		wantID      string
		wantFullID  string
	}{
		{
			name:        "containerd runtime prefix",
			raw:         "containerd://abcdef123456",
			wantRuntime: "containerd",
			wantID:      "abcdef123456",
			wantFullID:  "containerd://abcdef123456",
		},
		{
			name:        "cri-o runtime prefix",
			raw:         "cri-o://deadbeef",
			wantRuntime: "cri-o",
			wantID:      "deadbeef",
			wantFullID:  "cri-o://deadbeef",
		},
		{
			name:        "already stripped id",
			raw:         "abcdef123456",
			wantRuntime: "",
			wantID:      "abcdef123456",
			wantFullID:  "abcdef123456",
		},
		{
			name:        "trim whitespace",
			raw:         "  containerd://abcdef123456\n",
			wantRuntime: "containerd",
			wantID:      "abcdef123456",
			wantFullID:  "containerd://abcdef123456",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRuntimeContainerID(tc.raw)
			if err != nil {
				t.Fatalf("ParseRuntimeContainerID() error = %v", err)
			}
			if got.Runtime != tc.wantRuntime {
				t.Fatalf("expected runtime %q, got %q", tc.wantRuntime, got.Runtime)
			}
			if got.ID != tc.wantID {
				t.Fatalf("expected stripped id %q, got %q", tc.wantID, got.ID)
			}
			if got.FullID != tc.wantFullID {
				t.Fatalf("expected full id %q, got %q", tc.wantFullID, got.FullID)
			}
		})
	}
}

func TestParseRuntimeContainerIDRejectsEmptyID(t *testing.T) {
	cases := []string{"", "   ", "containerd://", "://abcdef"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseRuntimeContainerID(raw); err == nil {
				t.Fatalf("expected error for raw container id %q", raw)
			}
		})
	}
}

func TestParsePodJSONExtractsBusinessContainersOnly(t *testing.T) {
	podJSON := []byte(`{
	  "metadata": {
	    "namespace": "default",
	    "name": "risk-pod"
	  },
	  "spec": {
	    "nodeName": "worker-1",
	    "containers": [
	      {"name": "app"},
	      {"name": "sidecar"}
	    ],
	    "initContainers": [
	      {"name": "init-db"}
	    ],
	    "ephemeralContainers": [
	      {"name": "debugger"}
	    ]
	  },
	  "status": {
	    "containerStatuses": [
	      {
	        "name": "app",
	        "containerID": "containerd://app123"
	      },
	      {
	        "name": "sidecar",
	        "containerID": "containerd://sidecar456"
	      }
	    ],
	    "initContainerStatuses": [
	      {
	        "name": "init-db",
	        "containerID": "containerd://init789"
	      }
	    ],
	    "ephemeralContainerStatuses": [
	      {
	        "name": "debugger",
	        "containerID": "containerd://debug999"
	      }
	    ]
	  }
	}`)

	got, err := ParsePodJSON(podJSON)
	if err != nil {
		t.Fatalf("ParsePodJSON() error = %v", err)
	}
	if got.Namespace != "default" {
		t.Fatalf("expected namespace default, got %q", got.Namespace)
	}
	if got.Name != "risk-pod" {
		t.Fatalf("expected pod name risk-pod, got %q", got.Name)
	}
	if got.NodeName != "worker-1" {
		t.Fatalf("expected node worker-1, got %q", got.NodeName)
	}
	if len(got.Containers) != 2 {
		t.Fatalf("expected exactly 2 business containers, got %#v", got.Containers)
	}

	want := map[string]string{
		"app":     "app123",
		"sidecar": "sidecar456",
	}
	for _, container := range got.Containers {
		wantID, ok := want[container.Name]
		if !ok {
			t.Fatalf("unexpected container %q in parsed business containers", container.Name)
		}
		if container.Runtime != "containerd" {
			t.Fatalf("expected container %q runtime containerd, got %q", container.Name, container.Runtime)
		}
		if container.ContainerID != "containerd://"+wantID {
			t.Fatalf("expected container %q full id %q, got %q", container.Name, "containerd://"+wantID, container.ContainerID)
		}
		if container.RuntimeID != wantID {
			t.Fatalf("expected container %q runtime id %q, got %q", container.Name, wantID, container.RuntimeID)
		}
	}
}

func TestParsePodJSONKeepsMissingContainerIDForRetryDecision(t *testing.T) {
	podJSON := []byte(`{
	  "metadata": {"namespace": "default", "name": "pending-pod"},
	  "spec": {
	    "nodeName": "worker-1",
	    "containers": [
	      {"name": "app"},
	      {"name": "pending-sidecar"}
	    ]
	  },
	  "status": {
	    "containerStatuses": [
	      {"name": "app", "containerID": "containerd://app123"},
	      {"name": "pending-sidecar"}
	    ]
	  }
	}`)

	got, err := ParsePodJSON(podJSON)
	if err != nil {
		t.Fatalf("ParsePodJSON() error = %v", err)
	}
	if len(got.Containers) != 2 {
		t.Fatalf("expected 2 business containers including missing-id container, got %#v", got.Containers)
	}

	var missing ContainerTarget
	for _, container := range got.Containers {
		if container.Name == "pending-sidecar" {
			missing = container
			break
		}
	}
	if missing.Name == "" {
		t.Fatalf("expected pending-sidecar in parsed containers, got %#v", got.Containers)
	}
	if missing.ContainerID != "" || missing.Runtime != "" || missing.RuntimeID != "" {
		t.Fatalf("expected pending-sidecar to keep empty id fields for retry/skip decision, got %#v", missing)
	}
}

func TestParsePodJSONRejectsMalformedContainerID(t *testing.T) {
	podJSON := []byte(`{
	  "metadata": {"namespace": "default", "name": "bad-pod"},
	  "spec": {
	    "nodeName": "worker-1",
	    "containers": [{"name": "app"}]
	  },
	  "status": {
	    "containerStatuses": [
	      {"name": "app", "containerID": "containerd://"}
	    ]
	  }
	}`)

	_, err := ParsePodJSON(podJSON)
	if err == nil {
		t.Fatal("expected malformed containerID to be rejected")
	}
	if !strings.Contains(err.Error(), "app") {
		t.Fatalf("expected error to mention container name, got %v", err)
	}
}

func TestParseCRIInspectPID(t *testing.T) {
	cases := []struct {
		name string
		json string
		want int
	}{
		{
			name: "info pid",
			json: `{"info":{"pid":1234}}`,
			want: 1234,
		},
		{
			name: "status pid",
			json: `{"status":{"pid":2345}}`,
			want: 2345,
		},
		{
			name: "top-level pid",
			json: `{"pid":3456}`,
			want: 3456,
		},
		{
			name: "string pid",
			json: `{"info":{"pid":"4567"}}`,
			want: 4567,
		},
		{
			name: "prefer info pid",
			json: `{"info":{"pid":1234},"status":{"pid":2345},"pid":3456}`,
			want: 1234,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCRIInspectPID([]byte(tc.json))
			if err != nil {
				t.Fatalf("ParseCRIInspectPID() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected pid %d, got %d", tc.want, got)
			}
		})
	}
}

func TestCRICTLInspectArgsUsesK3sEndpointOverride(t *testing.T) {
	t.Setenv("RUNTIA_CRI_ENDPOINT", "unix:///run/k3s/containerd/containerd.sock")

	got := crictlInspectArgs("abc123")
	want := []string{"--runtime-endpoint", "unix:///run/k3s/containerd/containerd.sock", "inspect", "-o", "json", "abc123"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("expected crictl args %#v, got %#v", want, got)
	}
}

func TestCRICTLInspectArgsDefaultsToK3sEndpoint(t *testing.T) {
	t.Setenv("RUNTIA_CRI_ENDPOINT", " ")

	got := crictlInspectArgs("abc123")
	want := []string{"--runtime-endpoint", defaultK3sCRIEndpoint, "inspect", "-o", "json", "abc123"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("expected crictl args %#v, got %#v", want, got)
	}
}

func TestParseCRIInspectPIDRejectsMissingOrInvalidPID(t *testing.T) {
	cases := []string{
		`{}`,
		`{"info":{}}`,
		`{"info":{"pid":0}}`,
		`{"info":{"pid":-1}}`,
		`{"info":{"pid":"not-a-number"}}`,
		`{"info":{"pid":{}}}`,
	}

	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseCRIInspectPID([]byte(input)); err == nil {
				t.Fatalf("expected PID parse error for %s", input)
			}
		})
	}
}

func TestParseCgroupPathContent(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "cgroup v2 unified path",
			content: "0::/kubepods.slice/kubepods-burstable.slice/podabc/container.scope\n",
			want:    "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/podabc/container.scope",
		},
		{
			name:    "trim whitespace",
			content: "0::/kubepods/podabc/container\n\n",
			want:    "/sys/fs/cgroup/kubepods/podabc/container",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCgroupPathContent(tc.content)
			if err != nil {
				t.Fatalf("ParseCgroupPathContent() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected cgroup path %q, got %q", tc.want, got)
			}
		})
	}
}

func TestParseCgroupPathContentRejectsInvalidInput(t *testing.T) {
	cases := []string{
		"",
		"\n",
		"not-a-cgroup-line\n",
		"0::\n",
	}

	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseCgroupPathContent(input); err == nil {
				t.Fatalf("expected cgroup parse error for %q", input)
			}
		})
	}
}
