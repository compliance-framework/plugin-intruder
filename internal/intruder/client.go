package intruder

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/go-hclog"
)

const baseUrl = "https://api.intruder.io/v1"

type Client struct {
	BaseURL    string
	Logger     hclog.Logger
	HTTPClient *http.Client
}

type transport struct {
	token string
	base  http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	newRequest := req.Clone(req.Context())
	newRequest.Header.Set("Authorization", t.token)
	newRequest.Header.Set("accept", "application/json")
	return t.base.RoundTrip(newRequest)
}

func NewClient(logger hclog.Logger, token string) (*Client, error) {
	httpClient := &http.Client{
		Transport: &transport{
			token: token,
			base:  http.DefaultTransport,
		},
	}
	return &Client{
		BaseURL:    baseUrl,
		Logger:     logger,
		HTTPClient: httpClient,
	}, nil
}

func (c *Client) Do(method string, path string) (*http.Response, error) {
	apiUrl := fmt.Sprintf("%s/%s", c.BaseURL, path)
	c.Logger.Debug("Requesting", "method", method, "url", apiUrl)

	req, err := http.NewRequest(method, apiUrl, nil)
	if err != nil {
		return nil, err
	}
	return c.HTTPClient.Do(req)
}
