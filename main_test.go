package main

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/compliance-framework/agent/runner"
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

// fakeApiHelper records what the plugin sends to the agent.
type fakeApiHelper struct {
	subjectTemplates [][]*proto.SubjectTemplate
	riskTemplates    map[string][]*proto.RiskTemplate
	upsertErr        error
}

func (f *fakeApiHelper) CreateEvidence(context.Context, []*proto.Evidence) error {
	return nil
}

func (f *fakeApiHelper) UpsertRiskTemplates(_ context.Context, packageName string, templates []*proto.RiskTemplate) error {
	if f.riskTemplates == nil {
		f.riskTemplates = map[string][]*proto.RiskTemplate{}
	}
	f.riskTemplates[packageName] = templates
	return nil
}

func (f *fakeApiHelper) UpsertSubjectTemplates(_ context.Context, templates []*proto.SubjectTemplate) error {
	f.subjectTemplates = append(f.subjectTemplates, templates)
	return f.upsertErr
}

var _ runner.RunnerV2 = (*IntruderPlugin)(nil)

func TestInitRegistersIntruderTargetSubjectTemplate(t *testing.T) {
	plugin := &IntruderPlugin{Logger: hclog.NewNullLogger()}
	api := &fakeApiHelper{}

	resp, err := plugin.Init(&proto.InitRequest{}, api)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if resp == nil {
		t.Fatal("init returned a nil response")
	}

	if len(api.subjectTemplates) != 1 {
		t.Fatalf("expected one UpsertSubjectTemplates call, got %d", len(api.subjectTemplates))
	}
	templates := api.subjectTemplates[0]
	if len(templates) != 1 {
		t.Fatalf("expected one subject template, got %d", len(templates))
	}

	tmpl := templates[0]
	if tmpl.GetName() != "intruder-target" {
		t.Errorf("Name = %q, want %q", tmpl.GetName(), "intruder-target")
	}
	if tmpl.GetType() != proto.SubjectType_SUBJECT_TYPE_COMPONENT {
		t.Errorf("Type = %v, want %v", tmpl.GetType(), proto.SubjectType_SUBJECT_TYPE_COMPONENT)
	}
	if got, want := tmpl.GetTitleTemplate(), "Intruder Target: {{ .target }}"; got != want {
		t.Errorf("TitleTemplate = %q, want %q", got, want)
	}
	if got, want := tmpl.GetDescriptionTemplate(), "Host or URL scanned by Intruder ({{ .target }})"; got != want {
		t.Errorf("DescriptionTemplate = %q, want %q", got, want)
	}
	if got, want := tmpl.GetPurposeTemplate(), "Represents an Intruder scan target whose outstanding issues are assessed"; got != want {
		t.Errorf("PurposeTemplate = %q, want %q", got, want)
	}
	if got, want := tmpl.GetIdentityLabelKeys(), []string{"target"}; !slices.Equal(got, want) {
		t.Errorf("IdentityLabelKeys = %v, want %v", got, want)
	}

	var schemaKeys []string
	for _, schema := range tmpl.GetLabelSchema() {
		if schema.GetDescription() == "" {
			t.Errorf("label schema %q has no description", schema.GetKey())
		}
		schemaKeys = append(schemaKeys, schema.GetKey())
	}
	if want := []string{"target", "provider", "intruder_type"}; !slices.Equal(schemaKeys, want) {
		t.Errorf("LabelSchema keys = %v, want %v", schemaKeys, want)
	}

	if len(api.riskTemplates) != 0 {
		t.Errorf("expected no risk templates without policy paths, got %v", api.riskTemplates)
	}
}

func TestInitReturnsSubjectTemplateUpsertError(t *testing.T) {
	plugin := &IntruderPlugin{Logger: hclog.NewNullLogger()}
	upsertErr := errors.New("api unavailable")
	api := &fakeApiHelper{upsertErr: upsertErr}

	resp, err := plugin.Init(&proto.InitRequest{}, api)
	if !errors.Is(err, upsertErr) {
		t.Fatalf("expected the upsert error, got %v", err)
	}
	if resp != nil {
		t.Fatalf("expected a nil response on error, got %v", resp)
	}
}
