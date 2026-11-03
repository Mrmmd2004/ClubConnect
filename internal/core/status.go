package core

// BackendStatus and Status are what GET /status returns (the JSON field names are the API).
type BackendStatus struct {
	Name      string `json:"name"`
	Ready     bool   `json:"ready"`
	Healthy   bool   `json:"healthy"`
	LatencyMS int64  `json:"latency_ms"`
	UDP       bool   `json:"udp"`
	Variant   string `json:"variant,omitempty"` // which WARP route this engine uses
	Error     string `json:"error,omitempty"`
}

type Status struct {
	Version  string          `json:"version"`
	Running  bool            `json:"running"`
	RunMode  string          `json:"run_mode"`
	Variant  string          `json:"variant"` // WARP variant the running mode was started with
	LastMode string          `json:"last_mode"`
	Port     int             `json:"port"`
	Mode     string          `json:"mode"`
	Active   string          `json:"active"`
	Up       uint64          `json:"bytes_up"`
	Down     uint64          `json:"bytes_down"`
	Backends []BackendStatus `json:"backends"`
}
