package option

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/schema"
)

func TestVPNServerBypassSingleObjectAndSchema(t *testing.T) {
	var options EBPFLocalOptions
	if err := json.Unmarshal([]byte(`{"vpn_server_bypass":[{"enabled":true}]}`), &options); err == nil {
		t.Fatal("multiple VPN server bypass objects accepted")
	}
	generated, err := schema.Generate(context.Background(), reflect.TypeFor[EBPFLocalOptions]())
	if err != nil {
		t.Fatal(err)
	}
	documented, err := os.ReadFile("../docs/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var actual, stored map[string]any
	if err = json.Unmarshal(generated, &actual); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(documented, &stored); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"EBPFVPNServerBypassOptions", "EBPFLocalOptions"} {
		if !reflect.DeepEqual(actual["$defs"].(map[string]any)[name], stored["$defs"].(map[string]any)[name]) {
			t.Fatalf("documented %s schema differs from options", name)
		}
	}
}

func TestVPNServerBypassPortSchemaBounds(t *testing.T) {
	generated, err := schema.Generate(context.Background(), reflect.TypeFor[EBPFLocalOptions]())
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(generated, &document); err != nil {
		t.Fatal(err)
	}
	endpoint := document["$defs"].(map[string]any)["EBPFVPNServerBypassOptions"].(map[string]any)
	port := endpoint["properties"].(map[string]any)["port"].(map[string]any)
	for _, variant := range port["anyOf"].([]any) {
		node := variant.(map[string]any)
		if node["type"] == "array" {
			node = node["items"].(map[string]any)
		}
		if node["minimum"] != float64(1) || node["maximum"] != float64(65535) {
			t.Fatalf("VPN server bypass port bounds: %+v", node)
		}
	}
}
