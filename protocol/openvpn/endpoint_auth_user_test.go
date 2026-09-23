package openvpn

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthUserForSource(t *testing.T) {
	source := netip.MustParseAddr("10.200.1.7")
	server := &ServerEndpoint{usersBySource: map[netip.Addr]string{source: "dev-user"}}
	require.Equal(t, "dev-user", server.authUserForSource(source))
	require.Empty(t, server.authUserForSource(netip.MustParseAddr("10.200.1.8")))
}

func TestOpenVPNPacketSource(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], netip.MustParseAddr("10.200.1.7").AsSlice())
	require.Equal(t, netip.MustParseAddr("10.200.1.7"), openVPNPacketSource(packet))
	require.False(t, openVPNPacketSource([]byte{0x45}).IsValid())
}
