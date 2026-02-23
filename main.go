package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-intruder/internal/intruder"
	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type IntruderPlugin struct {
	Logger hclog.Logger

	config         *PluginConfig
	intruderClient *intruder.Client
}

type PluginConfig struct {
	Token   string `mapstructure:"token"`
	BaseUrl string `mapstructure:"baseUrl"`
}

func (c *PluginConfig) Validate() error {
	if c.Token == "" {
		return errors.New("token is required")
	}

	return nil
}

func (l *IntruderPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.Logger.Info("Configuring Intruder Plugin")

	config := &PluginConfig{}

	if err := mapstructure.Decode(req.Config, config); err != nil {
		l.Logger.Error("Error decoding config", "error", err)
		return nil, err
	}

	if err := config.Validate(); err != nil {
		l.Logger.Error("Error validating config", "error", err)
		return nil, err
	}

	l.config = config

	return &proto.ConfigureResponse{}, nil
}

func (l *IntruderPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	done := false
	ctx := context.TODO()

	if l.config == nil {
		return nil, errors.New("plugin is not configured")
	}

	client, err := intruder.NewClient(l.config.BaseUrl, l.Logger, l.config.Token)
	if err != nil {
		l.Logger.Error("Error creating Intruder client", "error", err)
		return nil, err
	}
	l.intruderClient = client

	targets, err := l.intruderClient.FetchTargets()
	if err != nil {
		l.Logger.Error("Error fetching targets from Intruder", "error", err)
		return nil, err
	}
	issueChan, errChan := l.FetchIssues(targets)

	for !done {
		select {
		case err, ok := <-errChan:
			if !ok {
				done = true
				continue
			}
			l.Logger.Error("Error fetching issues", "error", err)
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		case issueResult, ok := <-issueChan:
			if !ok {
				done = true
				continue
			}
			evidences, err := l.EvalPolicies(ctx, issueResult, req)

			if err != nil {
				l.Logger.Error("Error evaluating policies", "target", issueResult.Target.Address, "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
				l.Logger.Error("Error creating evidence", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

		}
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
}

type IssueResult struct {
	Target *intruder.Target
	Issues []intruder.Issue
	Err    error
}

func (l *IntruderPlugin) FetchIssues(targets []intruder.Target) (chan *IssueResult, chan error) {
	issueChan := make(chan *IssueResult)
	errChan := make(chan error)

	go func() {
		defer close(issueChan)
		defer close(errChan)

		for _, target := range targets {
			issues, err := l.intruderClient.FetchIssuesForTarget(target.Address)
			if err != nil {
				errChan <- fmt.Errorf("Unable to fetch issues for target %s: %w", target.Address, err)
				continue
			}
			issueChan <- &IssueResult{
				Target: &target,
				Issues: issues,
			}
		}

	}()
	return issueChan, errChan
}

func (l *IntruderPlugin) EvalPolicies(ctx context.Context, data *IssueResult, req *proto.EvalRequest) ([]*proto.Evidence, error) {
	var accumulatedErrors error
	evidences := make([]*proto.Evidence, 0)

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/intruder-target",
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("intruder-target/%s", data.Target.Address),
		},
	}
	components := []*proto.Component{
		{
			Type:        "target",
			Identifier:  "common-components/intruder-target",
			Title:       "Intruder Target",
			Description: "An intruder target represents an asset that has been registered with the SaaS-based vulnerability scanning platform intruder.io. It can represent various types of assets such as an external IP address, a domain, a sub-domain and an internal device.",
			Purpose:     "Intruder.io is a SaaS vulnerability scanning tool used to continuously monitor internet-facing systems and cloud assets for security weaknesses, helping identify, prioritise, and remediate vulnerabilities before they can be exploited by attackers.",
			Links: []*proto.Link{
				{
					Href: "https://www.intruder.io/",
					Rel:  policyManager.Pointer("component"),
					Text: policyManager.Pointer("Intruder Website"),
				},
			},
		},
	}
	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("intruder-target/%s", data.Target.Address),
			Type:       "intruder-target",
			Title:      fmt.Sprintf("Intruder Target %s", data.Target.Address),
			Props: []*proto.Property{
				{
					Name:  "address",
					Value: data.Target.Address,
				},
				{
					Name:  "intruder-id",
					Value: strconv.Itoa(data.Target.ID),
				},
				{
					Name:  "display-address",
					Value: data.Target.DisplayAddress,
				},
				{
					Name:  "status",
					Value: data.Target.TargetStatus,
				},
				{
					Name:  "type",
					Value: data.Target.Type,
				},
			},
			Links: []*proto.Link{
				{
					Href: fmt.Sprintf("https://portal.intruder.io/targets/%s", data.Target.ID),
					Text: policyManager.Pointer("Target Details"),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: "common-components/intruder-target",
				},
			},
		},
	}
	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework"),
				},
			},
			Props: nil,
		},
		{
			Title: "Continuous Compliance Framework - Intruder Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-intruder",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework' Intruder Plugin"),
				},
			},
			Props: nil,
		},
	}
	activities := []*proto.Activity{
		{
			Title: "Collect Intruder Data",
			Steps: []*proto.Step{
				{
					Title:       "Fetch target information",
					Description: "Fetch all targets from the Intruder API",
				},
				{
					Title:       "Fetch all issues associated with a target",
					Description: "Fetch all issues from the Intruder API specific for each target",
				},
			},
		},
	}
	for _, policyPath := range req.GetPolicyPaths() {
		for _, issue := range data.Issues {
			specificIssue := map[string]interface{}{
				"target": data.Target,
				"issue":  issue,
			}

			processor := policyManager.NewPolicyProcessor(
				l.Logger,
				map[string]string{
					"provider":    "intruder",
					"type":        "issue",
					"target":      data.Target.Address,
					"target_type": data.Target.Type,
					"issue_id":    strconv.Itoa(issue.ID),
				},
				subjects,
				components,
				inventory,
				actors,
				activities,
			)
			evidence, err := processor.GenerateResults(ctx, policyPath, specificIssue)
			evidences = slices.Concat(evidences, evidence)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}

	}

	return evidences, accumulatedErrors
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	intruder := &IntruderPlugin{
		Logger: logger,
	}

	logger.Info("Starting Intruder Plugin")
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: intruder,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
