//go:build android

package settings

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/mdlayher/wifi"
)

func TestSelectAndroidWIFIState(t *testing.T) {
	interfaces := []*wifi.Interface{
		{Index: 1, Type: wifi.InterfaceTypeAP},
		{Index: 2, Type: wifi.InterfaceTypeStation},
		{Index: 3, Type: wifi.InterfaceTypeStation},
	}
	state, err := selectAndroidWIFIState(interfaces, func(networkInterface *wifi.Interface) (*wifi.BSS, error) {
		if networkInterface.Index == 2 {
			return nil, os.ErrNotExist
		}
		return &wifi.BSS{SSID: "test", BSSID: net.HardwareAddr{0, 1, 2, 3, 4, 5}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.SSID != "test" || state.BSSID != "00:01:02:03:04:05" {
		t.Fatalf("unexpected WIFI state: %+v", state)
	}

	readErr := errors.New("read BSS")
	_, err = selectAndroidWIFIState(interfaces[1:2], func(*wifi.Interface) (*wifi.BSS, error) {
		return nil, readErr
	})
	if !errors.Is(err, readErr) {
		t.Fatalf("expected read error, got %v", err)
	}
}
