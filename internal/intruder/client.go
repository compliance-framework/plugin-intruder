package intruder

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/go-hclog"
)

const baseUrl = "https://api.intruder.io"

type Client struct {
	BaseURL    string
	Logger     hclog.Logger
	HTTPClient *http.Client
}

type Target struct {
	Address string
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

func NewClient(base string, logger hclog.Logger, token string) (*Client, error) {
	httpClient := &http.Client{
		Transport: &transport{
			token: token,
			base:  http.DefaultTransport,
		},
	}
	client := &Client{
		BaseURL:    baseUrl,
		Logger:     logger,
		HTTPClient: httpClient,
	}
	if base == "" {
		client.BaseURL = baseUrl
	} else {
		client.BaseURL = base
	}
	return client, nil

}

func (c *Client) Do(method string, path string) (*http.Response, error) {
	apiUrl := fmt.Sprintf("%s/v1/", c.BaseURL)
	apiUrl += strings.ReplaceAll(path, apiUrl, "")
	c.Logger.Debug("Requesting", "method", method, "url", apiUrl)

	req, err := http.NewRequest(method, apiUrl, nil)
	if err != nil {
		return nil, err
	}
	return c.HTTPClient.Do(req)
}

func (c *Client) FetchTargets() ([]Target, error) {
	allTargets := []Target{}
	limit := 25                                     //Intruder default
	next := fmt.Sprintf("targets/?limit=%d", limit) //Defaults to 0 offset + limit to start

	for {
		resp, err := c.Do(http.MethodGet, next)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			closeErr := resp.Body.Close()
			if closeErr != nil {
				c.Logger.Error("Failed to close response body", "error", closeErr)
			}
			return nil, fmt.Errorf("Unexpected status code: %d. Unable to decode response", resp.StatusCode)
		}
		var result struct {
			Next    string   `json:"next"`
			Targets []Target `json:"results"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			closeErr := resp.Body.Close()
			if closeErr != nil {
				c.Logger.Error("Failed to close response body", "error", closeErr)
			}
			return nil, err
		}

		closeErr := resp.Body.Close()
		if closeErr != nil {
			c.Logger.Error("Failed to close response body", "error", closeErr)
		}
		allTargets = append(allTargets, result.Targets...)
		c.Logger.Debug("Fetched targets", "count", len(result.Targets), "total", len(allTargets))

		next = result.Next
		if next == "" {
			break
		}
	}

	c.Logger.Debug("Fetched all targets", "total", len(allTargets))
	return allTargets, nil
}
