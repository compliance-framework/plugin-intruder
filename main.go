package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"

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

type IssueResult struct {
	Target                 *intruder.Target
	FixedOccurrences       []intruder.FixedOccurrence
	OutstandingOccurrences []intruder.Occurrence
	Title                  string
	Description            string
	Issue                  *intruder.Issue
}

func getIssueHash(issueTitle string) string {
	hasher := md5.New()
	hasher.Write([]byte(issueTitle))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (l *IntruderPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if l.config == nil {
		return nil, errors.New("plugin is not configured")
	}

	client, err := intruder.NewClient(l.config.BaseUrl, l.Logger, l.config.Token)
	if err != nil {
		l.Logger.Error("Error creating Intruder client", "error", err)
		return nil, err
	}
	l.intruderClient = client

	targets, err := l.intruderClient.FetchAllTargets()
	if err != nil {
		l.Logger.Error("Error fetching targets from Intruder", "error", err)
		return nil, err
	}

	if len(targets) == 0 {
		l.Logger.Trace("Execution completed. No targets found")
		return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
	}

	errCh := make(chan error, 1)
	var wg sync.WaitGroup

	for i := range targets {
		target := targets[i]
		wg.Add(1)

		go func(target intruder.Target) {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

			if err := l.processTarget(ctx, target, req, apiHelper); err != nil {
				select {
				case errCh <- err:
					cancel()
				default:
				}
			}
		}(target)
	}

	wg.Wait()

	select {
	case err := <-errCh:
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	default:
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
}

func (l *IntruderPlugin) processTarget(ctx context.Context, target intruder.Target, req *proto.EvalRequest, apiHelper runner.ApiHelper) error {
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	l.Logger.Trace("Processing target", "target", target.Address)
	fixedOccurrences, err := l.intruderClient.FetchFixedOccurrencesForTarget(target.Address)
	if err != nil {
		l.Logger.Error("Unable to fetch fixed occurrences for target", "target", target.Address, "error", err)
		return err
	}

	issues, err := l.intruderClient.FetchIssuesForTarget(target.Address)
	if err != nil {
		l.Logger.Error("Unable to fetch issues for target", "target", target.Address, "error", err)
		return err
	}

	collatedIssues := make(map[string]struct {
		issue intruder.Issue
		fixed []intruder.FixedOccurrence
	})

	for _, issue := range issues {
		group := collatedIssues[issue.Title]
		group.issue = issue
		collatedIssues[issue.Title] = group
	}

	for _, fixedOccurrence := range fixedOccurrences {
		group := collatedIssues[fixedOccurrence.Title]
		group.fixed = append(group.fixed, fixedOccurrence)
		collatedIssues[fixedOccurrence.Title] = group
	}

	for _, issue := range collatedIssues {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		outstandingIssue := issue.issue
		issueTitle := outstandingIssue.Title
		issueDescription := outstandingIssue.Description
		if issueTitle == "" && len(issue.fixed) > 0 {
			issueTitle = issue.fixed[0].Title
		}
		if issueDescription == "" && len(issue.fixed) > 0 {
			issueDescription = issue.fixed[0].Description
		}

		issueResult := &IssueResult{
			Target:                 &target,
			OutstandingOccurrences: outstandingIssue.Occurrences,
			FixedOccurrences:       issue.fixed,
			Title:                  issueTitle,
			Description:            issueDescription,
			Issue:                  &outstandingIssue,
		}

		l.Logger.Trace("Evaluating policies for issue against target", "target", issueResult.Target.Address, "issue", issueResult.Title)
		evidences, err := l.EvalPolicies(ctx, issueResult, req)
		if err != nil {
			l.Logger.Error("Error evaluating policies", "target", issueResult.Target.Address, "error", err)
			return err
		}

		if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
			l.Logger.Error("Error creating evidence", "target", issueResult.Target.Address, "error", err)
			return err
		}
	}

	return nil
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
					Href: fmt.Sprintf("https://portal.intruder.io/targets/%d", data.Target.ID),
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
		uidHash := getIssueHash(data.Title)

		processor := policyManager.NewPolicyProcessor(
			l.Logger,
			map[string]string{
				"provider":      "intruder",
				"intruder_type": "issue",
				"target":        data.Target.Address,
				"_issue_hash":   uidHash,
			},
			subjects,
			components,
			inventory,
			actors,
			activities,
		)

		evidence, err := processor.GenerateResults(ctx, policyPath, data)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
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
