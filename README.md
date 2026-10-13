# Compliance Framework - Intruder plugin

Fetches information regarding issues raised via intruder.io

## Authentication

To authenticate this plugin, you must provide an intruder.io api token. Its recommended to use a service account with an attached token rather than an individuals. 

You can find instructions on how to create a token [here](https://developers.intruder.io/docs/creating-an-access-token)

## Configuration

```yaml
plugins:
  intruder:
    config:
      token: "xxxxxxx-yyyyyyy-zzzzzz"
      baseUrl: "http://api.com:1234" (optional)
```

## Subjects

The plugin speaks protocol v2. When the agent calls `Init`, it registers one subject
template with the API, plus any risk templates the configured policies declare:

| Field | Value |
|---|---|
| Name | `intruder-target` |
| Type | component |
| Title | `Intruder Target: {{ .target }}` |
| Description | `Host or URL scanned by Intruder ({{ .target }})` |
| Purpose | `Represents an Intruder scan target whose outstanding issues are assessed` |
| Identity label | `target` |

Evidence carries these labels, which the template describes:

- `target`: the Intruder target address (a hostname, IP address or URL);
- `provider`: always `intruder`;
- `intruder_type`: the kind of Intruder record evaluated, `issue` today.

Evidence also carries `_issue_hash` (a hash of the issue title), which tells the issues
of one target apart. It is per issue, so it is not part of the subject.

## Policies

When writing OPA/Rego policies for this plugin, they must be added under the `compliance_framework` Rego package:

```rego
# deny_critical_severity.rego
# package compliance_framework.[YOUR_RULE_PATH]
package compliance_framework.deny_critical_severity
```

### Policy data

Any `policy_data` set on this plugin's block in the agent configuration is passed
to every policy evaluation and is available to Rego as `data.<key>`. The key below
is only an example: your policies decide which keys they read.

```yaml
plugins:
  intruder:
    config:
      token: "xxxxxxx-yyyyyyy-zzzzzz"
    policy_data:
      ignored_issue_titles:
        - "Example issue"
```

## Releases

This plugin is released using GoReleaser to build binaries, and GOOCI to upload artifacts to OCI,
which will ensure a binary is built for most OS and Architecture combinations.

You can find the binaries on each release of this plugin in the GitHub Releases page.

You can find the OCI implementations in the GitHub Packages page.
