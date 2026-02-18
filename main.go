package main

import (
	"errors"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type IntruderPlugin struct {
	logger hclog.Logger

	config *PluginConfig
}

type PluginConfig struct {
	Token string `mapstructure:"token"`
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
	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
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
