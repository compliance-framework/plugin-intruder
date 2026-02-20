package main

import (
	"errors"
	"fmt"
	"sync"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-intruder/internal/intruder"
	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type IntruderPlugin struct {
	logger hclog.Logger

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
	l.logger.Info("Configuring Intruder Plugin")

	config := &PluginConfig{}

	if err := mapstructure.Decode(req.Config, config); err != nil {
		l.logger.Error("Error decoding config", "error", err)
		return nil, err
	}

	if err := config.Validate(); err != nil {
		l.logger.Error("Error validating config", "error", err)
		return nil, err
	}

	l.config = config

	return &proto.ConfigureResponse{}, nil
}

func (l *IntruderPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	if l.config == nil {
		return nil, errors.New("plugin is not configured")
	}

	client, err := intruder.NewClient(l.config.BaseUrl, l.logger, l.config.Token)
	if err != nil {
		l.logger.Error("Error creating Intruder client", "error", err)
		return nil, err
	}
	l.intruderClient = client

	data, err := l.CollateData()
	if err != nil {
		l.logger.Error("Error collating data", "error", err)
		return nil, err
	}

	l.logger.Info("Collated Intruder data", "targets", len(data.Targets), "issues", len(data.Issues))

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
}

type IntruderData struct {
	Targets []intruder.Target
	Issues  []intruder.Issue
}

func (l *IntruderPlugin) CollateData() (*IntruderData, error) {
	data := &IntruderData{}

	targets, err := l.intruderClient.FetchTargets()
	if err != nil {
		l.logger.Error("Error fetching targets from Intruder", "error", err)
		return nil, err
	}
	data.Targets = targets

	issues, issErr := l.FetchIssuesForAllTargets(targets)
	if issErr != nil {
		l.logger.Error("Error fetching issues for targets from Intruder", "error", issErr)
		return nil, issErr
	}
	data.Issues = issues

	return data, nil

}

func (l *IntruderPlugin) FetchIssuesForAllTargets(targets []intruder.Target) ([]intruder.Issue, error) {
	type issueResult struct {
		issues []intruder.Issue
		err    error
	}

	issuesChan := make(chan issueResult, len(targets))
	var wg sync.WaitGroup

	for _, target := range targets {
		wg.Go(func() {
			issues, err := l.intruderClient.FetchIssuesForTarget(target.Address)
			if err != nil {
				issuesChan <- issueResult{err: fmt.Errorf("target %s: %w", target.Address, err)}
				return
			}
			issuesChan <- issueResult{issues: issues}
		})
	}

	go func() {
		wg.Wait()
		close(issuesChan)
	}()

	allIssues := make([]intruder.Issue, 0)
	for result := range issuesChan {
		if result.err != nil {
			return nil, result.err
		}
		allIssues = append(allIssues, result.issues...)
	}

	return allIssues, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	intruder := &IntruderPlugin{
		logger: logger,
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
