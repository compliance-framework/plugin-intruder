package intruder

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
	ID             int    `json:"id"`
	Address        string `json:"address"`
	DisplayAddress string `json:"display_address"`
	TargetStatus   string `json:"target_status"`
	Type           string `json:"target_type"`
}

type Issue struct {
	TargetAddress     string
	ID                int          `json:"id"`
	Severity          string       `json:"severity"`
	Title             string       `json:"title"`
	Description       string       `json:"description"`
	Remediation       string       `json:"remediation"`
	ExploitLikelihood string       `json:"exploit_likelihood"`
	CVSSScore         float32      `json:"cvss_score"`
	Occurrences       []Occurrence `json:"-"`
}

type Occurrence struct {
	ID        int    `json:"occurrence_id"`
	FirstSeen string `json:"first_seen_at"`
}

type FixedOccurrence struct {
	Occurrence
	Title        string `json:"title"`
	RemediatedAt string `json:"remediated_at"`
	Description  string `json:"description"`
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
		base = baseUrl
	}
	client.BaseURL = base
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

func (c *Client) FetchAllTargets() ([]Target, error) {
	allTargets := make([]Target, 0)
	limit := 25                                                        //Intruder default
	next := fmt.Sprintf("targets/?limit=%d&target_status=live", limit) //Defaults to 0 offset + limit to start

	for next != "" {
		result, err := fetchAPIEndpoint[struct {
			Next    string   `json:"next"`
			Targets []Target `json:"results"`
		}](c, next)
		if err != nil {
			return nil, err
		}
		allTargets = append(allTargets, result.Targets...)
		c.Logger.Debug("Fetched targets", "count", len(result.Targets), "total", len(allTargets))
		next = result.Next
	}

	c.Logger.Debug("Fetched all targets", "total", len(allTargets))
	return allTargets, nil
}

func fetchAPIEndpoint[T any](c *Client, url string) (T, error) {
	var result T

	resp, err := c.Do(http.MethodGet, url)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, err
	}
	return result, nil
}

func (c *Client) FetchIssuesForTarget(targetAddress string) ([]Issue, error) {
	allIssues := make([]Issue, 0)
	limit := 25                                                                                     //Intruder default
	next := fmt.Sprintf("issues/?target_addresses=%s&snoozed=false&limit=%d", targetAddress, limit) //Defaults to 0 offset + limit to start

	for {
		result, err := fetchAPIEndpoint[struct {
			Next   string  `json:"next"`
			Issues []Issue `json:"results"`
		}](c, next)
		if err != nil {
			return nil, err
		}
		allIssues = append(allIssues, result.Issues...)
		c.Logger.Debug("Fetched issues for target", "target", targetAddress, "count", len(result.Issues), "total", len(allIssues))

		next = result.Next
		if next == "" {
			break
		}
	}

	c.Logger.Debug("Fetched all issues for target", "target", targetAddress, "total", len(allIssues))
	for i := range allIssues {
		issue := &allIssues[i]

		occurrences, err := c.FetchOccurrencesForTargetIssue(targetAddress, issue.ID)
		if err != nil {
			c.Logger.Error("Failed to fetch occurrences for issue of target", "target", targetAddress, "issue_id", issue.ID, "error", err)
			continue
		}

		issue.TargetAddress = targetAddress
		issue.Occurrences = occurrences
	}
	return allIssues, nil
}

func (c *Client) FetchOccurrencesForTargetIssue(targetAddress string, issueID int) ([]Occurrence, error) {
	allOccurrences := make([]Occurrence, 0)
	limit := 25                                                                                               //Intruder default
	next := fmt.Sprintf("issues/%d/occurrences/?target_addresses=%s&limit=%d", issueID, targetAddress, limit) //Defaults to 0 offset + limit to start

	for {
		result, err := fetchAPIEndpoint[struct {
			Next        string       `json:"next"`
			Occurrences []Occurrence `json:"results"`
		}](c, next)
		if err != nil {
			return nil, err
		}
		allOccurrences = append(allOccurrences, result.Occurrences...)
		c.Logger.Debug("Fetched occurrences for issue", "issue", strconv.Itoa(issueID), "count", len(result.Occurrences), "total", len(allOccurrences))

		next = result.Next
		if next == "" {
			break
		}
	}

	c.Logger.Debug("Fetched all occurrences for issue on target", "target", targetAddress, "issue", strconv.Itoa(issueID), "total", len(allOccurrences))

	return allOccurrences, nil
}

func (c *Client) FetchFixedOccurrencesForTarget(targetAddress string) ([]FixedOccurrence, error) {
	allOccurrences := make([]FixedOccurrence, 0)
	limit := 25                                                                                  //Intruder default
	next := fmt.Sprintf("occurrences/fixed/?target_addresses=%s&limit=%d", targetAddress, limit) //Defaults to 0 offset + limit to start

	for {
		result, err := fetchAPIEndpoint[struct {
			Next        string            `json:"next"`
			Occurrences []FixedOccurrence `json:"results"`
		}](c, next)
		if err != nil {
			return nil, err
		}
		allOccurrences = append(allOccurrences, result.Occurrences...)
		c.Logger.Debug("Fetched occurrences for target", "target", targetAddress, "count", len(result.Occurrences), "total", len(allOccurrences))

		next = result.Next
		if next == "" {
			break
		}
	}

	c.Logger.Debug("Fetched all fixed occurrences for target", "target", targetAddress, "total", len(allOccurrences))

	return allOccurrences, nil
}
