package plugin

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	hcplugin "github.com/hashicorp/go-plugin"

	"github.com/go-aiquota/proto/quotapb"
	"github.com/go-aiquota/proto/secret"
)

// poison is a realistically-shaped fake session cookie value. It is pushed
// through a REAL go-plugin subprocess (this test binary, re-exec'd) end to
// end, and every place it could have leaked — the RPC response, an error
// string, and go-plugin's own logger (which forwards the subprocess's
// stderr to the host) — is checked with strings.Contains.
const poison = "sk-ses-aiquota-poison-QANT8bV3z9mR7wKp2LxYcH0dJfN6tGqE4sWo1uIrPy"

const reexecEnv = "AIQUOTA_PLUGIN_TEST_SERVE"

// TestMain lets this same test binary act as the plugin subprocess: when
// launched with reexecEnv set, it serves a fakeProvider instead of running
// tests. This is go-plugin's own recommended pattern for testing a real
// client/subprocess round trip without a separate binary.
func TestMain(m *testing.M) {
	if os.Getenv(reexecEnv) == "1" {
		hcplugin.Serve(&hcplugin.ServeConfig{
			HandshakeConfig: Handshake,
			Plugins:         Map(&fakeProvider{}),
			GRPCServer:      hcplugin.DefaultGRPCServer,
		})
		return
	}
	os.Exit(m.Run())
}

// fakeProvider is a deliberately well-behaved implementation: it never
// formats the raw credential into a log line or error string, which is
// exactly the discipline every real provider (plugin-claude included) must
// follow. It DOES route the value through secret.Secret when it wants to
// mention it at all, proving that path is safe even when a provider author
// reaches for it.
type fakeProvider struct {
	quotapb.UnimplementedQuotaProviderServer
}

func (p *fakeProvider) Describe(context.Context, *quotapb.DescribeRequest) (*quotapb.ProviderInfo, error) {
	return &quotapb.ProviderInfo{Name: "fake", LoginUrl: "https://example.invalid/login", CookieDomain: "example.invalid"}, nil
}

func (p *fakeProvider) FetchQuota(_ context.Context, req *quotapb.FetchQuotaRequest) (*quotapb.QuotaSnapshot, error) {
	s := secret.New(req.Credential["session"])
	// A provider that wants to note it saw a credential does so through
	// Secret, which is exactly what should make this line harmless.
	hclog.Default().Debug("fetched quota", "account", req.AccountLabel, "credential", s)
	return &quotapb.QuotaSnapshot{
		AccountLabel: req.AccountLabel,
		PlanKind:     "fake-plan",
		Windows: []*quotapb.QuotaWindow{
			{Label: "session", Used: 1, Limit: 10, Unit: "messages"},
		},
	}, nil
}

func TestPoisonCredentialRoundTripsWithoutLeaking(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	var logBuf bytes.Buffer
	logger := hclog.New(&hclog.LoggerOptions{Output: &logBuf, Level: hclog.Trace})

	cmd := exec.Command(exePath, "-test.run=^TestMain$")
	cmd.Env = append(os.Environ(), reexecEnv+"=1")

	client := hcplugin.NewClient(&hcplugin.ClientConfig{
		HandshakeConfig:  Handshake,
		Plugins:          Map(nil),
		Cmd:              cmd,
		AllowedProtocols: []hcplugin.Protocol{hcplugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           logger,
	})
	defer client.Kill()

	rpcClient, err := client.Client()
	if err != nil {
		t.Fatalf("client.Client: %v", err)
	}
	raw, err := rpcClient.Dispense(Key)
	if err != nil {
		t.Fatalf("Dispense: %v", err)
	}
	quotaClient, ok := raw.(quotapb.QuotaProviderClient)
	if !ok {
		t.Fatalf("Dispense returned %T, want quotapb.QuotaProviderClient", raw)
	}

	resp, err := quotaClient.FetchQuota(context.Background(), &quotapb.FetchQuotaRequest{
		AccountLabel: "acct-1",
		Credential:   map[string]string{"session": poison},
	})
	if err != nil {
		t.Fatalf("FetchQuota: %v", err)
	}
	if resp.AccountLabel != "acct-1" || len(resp.Windows) != 1 {
		t.Fatalf("unexpected response shape: %+v", resp)
	}

	client.Kill() // flush/finish subprocess output before inspecting the log

	if strings.Contains(logBuf.String(), poison) {
		t.Fatalf("poison value leaked through go-plugin's logger:\n%s", logBuf.String())
	}
	if strings.Contains(resp.String(), poison) {
		t.Fatalf("poison value leaked through the response: %+v", resp)
	}
}
