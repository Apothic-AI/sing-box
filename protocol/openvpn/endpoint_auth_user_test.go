package openvpn

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/route/rule"
	ovpn "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/stretchr/testify/require"
)

func TestServerDataAuthUserFlowsIntoAuthUserRule(t *testing.T) {
	source := netip.MustParseAddr("10.200.1.7")
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], source.AsSlice())
	buffer := buf.As(packet)
	defer buffer.Release()
	server := &ServerEndpoint{usersBySource: make(map[netip.Addr]string)}
	server.rememberAuthUser(ovpn.ServerDataBuffer{
		AuthUser: "dev-user",
		Buffer:   buffer,
	})

	// The userspace device can report an IPv4-mapped source address. The full
	// buffer -> source map -> routed metadata path must normalize both forms.
	seen := ""
	server.router = &authUserPreMatchRouter{seen: &seen}
	verdict := server.JudgeFlow(
		6, // TCP
		netip.AddrPortFrom(netip.MustParseAddr("::ffff:10.200.1.7"), 1234),
		netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), 443), nil,
	)
	require.Equal(t, "dev-user", seen)
	require.Equal(t, tun.ActionReject, verdict.Action)
}

type authUserPreMatchRouter struct {
	adapter.Router
	seen *string
}

func (r *authUserPreMatchRouter) PreMatch(metadata adapter.InboundContext, _ []byte) adapter.PreMatchResult {
	*r.seen = metadata.User
	if rule.NewAuthUserItem([]string{"dev-user"}).Match(&metadata) {
		return adapter.PreMatchResult{Action: adapter.PreMatchReject}
	}
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

func TestOpenVPNPacketSource(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], netip.MustParseAddr("10.200.1.7").AsSlice())
	require.Equal(t, netip.MustParseAddr("10.200.1.7"), openVPNPacketSource(packet))
	require.False(t, openVPNPacketSource([]byte{0x45}).IsValid())
}
