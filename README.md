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
```

## Policies

When writing OPA/Rego policies for this plugin, they must be added under the `compliance_framework` Rego package:

```rego
# deny_critical_severity.rego
# package compliance_framework.[YOUR_RULE_PATH]
package compliance_framework.deny_critical_severity
```

## Releases

This plugin is released using GoReleaser to build binaries, and GOOCI to upload artifacts to OCI,
which will ensure a binary is built for most OS and Architecture combinations.

You can find the binaries on each release of this plugin in the GitHub Releases page.

You can find the OCI implementations in the GitHub Packages page.
