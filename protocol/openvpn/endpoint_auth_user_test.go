package openvpn

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/route/rule"
	ovpn "github.com/sagernet/sing-openvpn"
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
	metadata := adapter.InboundContext{User: server.authUserForSource(
		netip.MustParseAddr("::ffff:10.200.1.7"),
	)}
	require.True(t, rule.NewAuthUserItem([]string{"dev-user"}).Match(&metadata))
}

func TestOpenVPNPacketSource(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], netip.MustParseAddr("10.200.1.7").AsSlice())
	require.Equal(t, netip.MustParseAddr("10.200.1.7"), openVPNPacketSource(packet))
	require.False(t, openVPNPacketSource([]byte{0x45}).IsValid())
}
