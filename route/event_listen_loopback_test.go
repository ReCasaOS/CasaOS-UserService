package route

import "testing"

// The listener sends the boot's secret with its handshake, so the bus it dials
// must be this box's own: message-bus.url could name any host.
func TestTheSecretGoesToALoopbackBusOnly(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1":    true,
		"::1":          true,
		"localhost":    true,
		"192.168.1.20": false,
		"example.com":  false,
		"":             false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}
