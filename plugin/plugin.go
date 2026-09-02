// Package plugin is the hashicorp/go-plugin wiring shared by go-aiquota/tray
// (the host) and every provider plugin: the handshake, the plugin map, and
// the GRPCPlugin adapter for quotapb.QuotaProvider. A provider registers its
// implementation through this package; the host launches and dials it
// through this package — neither side hand-rolls the go-plugin boilerplate.
package plugin

import (
	"context"
	"os/exec"

	hcplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/go-aiquota/proto/quotapb"
)

// Key is the name every provider registers its GRPCPlugin under in the
// go-plugin plugin map, and the name the host looks it up by.
const Key = "quota_provider"

// Handshake is the magic-cookie handshake go-plugin uses to confirm a
// launched subprocess really is a go-aiquota provider (and not some
// unrelated program that happens to be on PATH) before speaking gRPC to it.
var Handshake = hcplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "AIQUOTA_PLUGIN",
	MagicCookieValue: "quota-provider-v1",
}

// GRPCPlugin adapts a quotapb.QuotaProviderServer to go-plugin's GRPCPlugin
// interface. A provider sets Impl and serves it; the host leaves Impl nil
// and only uses GRPCClient (go-plugin calls whichever side applies).
type GRPCPlugin struct {
	hcplugin.NetRPCUnsupportedPlugin
	Impl quotapb.QuotaProviderServer
}

// GRPCServer registers Impl on the provider's gRPC server. Called by
// go-plugin inside the plugin subprocess.
func (p *GRPCPlugin) GRPCServer(_ *hcplugin.GRPCBroker, s *grpc.Server) error {
	quotapb.RegisterQuotaProviderServer(s, p.Impl)
	return nil
}

// GRPCClient returns a quotapb.QuotaProviderClient bound to the plugin's
// connection. Called by go-plugin inside the host process.
func (p *GRPCPlugin) GRPCClient(_ context.Context, _ *hcplugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return quotapb.NewQuotaProviderClient(c), nil
}

// Map is the go-plugin plugin map both sides register: one entry, at [Key],
// resolving to a fresh GRPCPlugin. The host uses it empty (Impl is set
// server-side only); a provider passes a Map with Impl populated to
// hcplugin.Serve.
func Map(impl quotapb.QuotaProviderServer) map[string]hcplugin.Plugin {
	return map[string]hcplugin.Plugin{
		Key: &GRPCPlugin{Impl: impl},
	}
}

// ClientConfig returns the hcplugin.ClientConfig the host uses to launch and
// dial a provider subprocess at binaryPath: gRPC only, and AutoMTLS so the
// credential passed in each FetchQuota call rides an ephemeral per-launch
// TLS connection over the loopback socket rather than plaintext.
func ClientConfig(binaryPath string) hcplugin.ClientConfig {
	return hcplugin.ClientConfig{
		HandshakeConfig:  Handshake,
		Plugins:          Map(nil),
		Cmd:              exec.Command(binaryPath),
		AllowedProtocols: []hcplugin.Protocol{hcplugin.ProtocolGRPC},
		AutoMTLS:         true,
	}
}
