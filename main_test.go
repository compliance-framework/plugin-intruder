package main

import (
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConfigureStoresPolicyData(t *testing.T) {
	policyData, err := structpb.NewStruct(map[string]interface{}{
		"ignored_issue_titles": []interface{}{"Example issue"},
	})
	if err != nil {
		t.Fatalf("build policy data: %v", err)
	}

	plugin := &IntruderPlugin{Logger: hclog.NewNullLogger()}
	config := map[string]string{"token": "test-token"}

	if _, err := plugin.Configure(&proto.ConfigureRequest{Config: config, PolicyData: policyData}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	titles, ok := plugin.policyData["ignored_issue_titles"].([]interface{})
	if !ok || len(titles) != 1 || titles[0] != "Example issue" {
		t.Fatalf("unexpected policy data: %#v", plugin.policyData)
	}

	if _, err := plugin.Configure(&proto.ConfigureRequest{Config: config}); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	if plugin.policyData != nil {
		t.Fatalf("expected policy data to be cleared, got %#v", plugin.policyData)
	}
}
