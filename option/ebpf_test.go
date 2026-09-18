package option

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/schema"
)

func TestEndpointBypassSingleObjectAndSchema(t *testing.T) {
	var options EBPFLocalOptions
	if err := json.Unmarshal([]byte(`{"endpoint_connected_bypass":[{"enabled":true}]}`), &options); err == nil {
		t.Fatal("multiple endpoint objects accepted")
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
	for _, name := range []string{"EBPFEndpointConnectedBypassOptions", "EBPFLocalOptions"} {
		if !reflect.DeepEqual(actual["$defs"].(map[string]any)[name], stored["$defs"].(map[string]any)[name]) {
			t.Fatalf("documented %s schema differs from options", name)
		}
	}
}
