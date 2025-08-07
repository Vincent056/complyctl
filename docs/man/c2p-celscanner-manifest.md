% C2P-CELSCANNER-MANIFEST.JSON(5) complyctl CELScanner Plugin Configuration
% Vincent056 <wenshen@redhat.com>
% Aug 2025

# NAME

c2p-celscanner-manifest.json - Configuration file for the CELScanner plugin used by complyctl

# DESCRIPTION

This file defines the metadata and runtime configuration options for the `celscanner-plugin`, a plugin to be used with `complyctl`.

It can be either JSON or YAML formatted. The plugin is typically configured in the main complyctl manifest file:

**manifest.yaml** or **manifest.json**

Some configuration options used by `celscanner-plugin` can be overridden by using a drop-in file in "`/etc/complyctl/config.d/`":

**/etc/complyctl/config.d/c2p-celscanner-manifest.json**

For some specific cases, it is also possible to inform a custom configuration directory to override `/etc/complyctl/config.d`.
For example, the following command will try to locate and read custom settings from manifest files hosted in `/tmp/plugins-conf` instead of `/etc/complyctl/config.d`:

`complyctl generate --plugin-config /tmp/plugins-conf`

See complyctl(1) for more details about the available options.

# FILE FORMAT

The configuration is typically part of the complyctl manifest with the following structure:

```yaml
assessment-plan: assessment-plan.json
plugins:
  - name: celscanner-plugin
    path: /path/to/plugin  # Optional, defaults to system path
    config:
      # Configuration options here
```

# CONFIGURATION OPTIONS

## Core Options

**workspace** (string)
Path to the workspace directory where plugin files will be stored.
Default: `./workspace`

**target_name** (string)
Name of the target system being scanned.
Default: `"target"`

**target_type** (string)
Type of the target system (e.g., "kubernetes-cluster", "linux-system").
Default: `"system"`

**target_id** (string)
Unique identifier for the target system.
Default: `"default"`

**namespace** (string)
Comma-separated list of Kubernetes namespaces to include.
Default: `"default"`

## File Paths

**mapping_file** (string)
Path to custom CEL expression mapping file (YAML format).
Default: `"mappings.yaml"`

**rules_dir** (string)
Path to directory containing CEL rule YAML files.
Default: `"rules"`

**results_file** (string)
Filename for scan results.
Default: `"cel-results.yaml"`

## Feature Flags

**enable_kubernetes** (boolean)
Enable Kubernetes resource fetching.
Default: `false`

**enable_filesystem** (boolean)
Enable filesystem fetching.
Default: `true`

**enable_http** (boolean)
Enable HTTP fetching.
Default: `false`

**enable_system** (boolean)
Enable system command execution (limited to service status).
Default: `false`

## RPC Server Options

**use_rpc_server** (boolean)
Use CEL RPC Server instead of local evaluation.
Default: `false`

**cel_server_address** (string)
Address of the CEL RPC Server.
Default: `"localhost:50051"`

**cel_server_timeout** (integer)
Timeout for RPC calls in seconds.
Default: `30`

**cel_server_use_tls** (boolean)
Use TLS for RPC connections.
Default: `false`

**cel_server_cert_file** (string)
Path to TLS certificate file.

**cel_server_key_file** (string)
Path to TLS key file.

## Scanner Configuration

**enable_debug_logging** (boolean)
Enable verbose debug logging.
Default: `false`

**include_namespaces** (string)
Comma-separated list of namespaces to include (Kubernetes only).
Default: `""`

**exclude_namespaces** (string)
Comma-separated list of namespaces to exclude (Kubernetes only).
Default: `""`

**resource_types** (string)
Comma-separated list of Kubernetes resource types to scan.
Default: `"pods,deployments,services"`

**profile** (string)
OSCAL profile ID to use for rule selection.
Default: `""`

# EXAMPLES

## Basic Configuration

```yaml
assessment-plan: assessment-plan.json
plugins:
  - name: celscanner-plugin
    config:
      workspace: ./compliance-workspace
      enable_kubernetes: true
      target_name: my-cluster
```

## Advanced Configuration with RPC Server

```yaml
plugins:
  - name: celscanner-plugin
    config:
      workspace: /var/lib/compliance
      target_name: production-cluster
      target_type: kubernetes-cluster
      
      # Enable all fetchers except HTTP
      enable_kubernetes: true
      enable_filesystem: true
      enable_system: true
      enable_http: false
      
      # Use RPC server
      use_rpc_server: true
      cel_server_address: cel-server.compliance:50051
      cel_server_use_tls: true
      cel_server_cert_file: /etc/pki/cel/client.crt
      cel_server_key_file: /etc/pki/cel/client.key
      
      # Scanner settings
      include_namespaces: production,staging
      exclude_namespaces: kube-system,kube-public
      resource_types: pods,deployments,services,configmaps,secrets,networkpolicies
      
      # Custom mapping
      mapping_file: /etc/compliance/cel-mappings.yaml
```

## Environment-Specific Configuration

```yaml
plugins:
  - name: celscanner-plugin
    config:
      workspace: ./workspace
      enable_kubernetes: true

environments:
  development:
    plugins:
      - name: celscanner-plugin
        config:
          target_name: dev-cluster
          enable_debug_logging: true
          include_namespaces: dev,test
  
  production:
    plugins:
      - name: celscanner-plugin
        config:
          target_name: prod-cluster
          use_rpc_server: true
          cel_server_address: cel-rpc.prod:50051
```

## Drop-in Configuration File

Create `/etc/complyctl/config.d/c2p-celscanner-manifest.json`:

```json
{
  "name": "celscanner-plugin",
  "config": {
    "enable_kubernetes": true,
    "cel_server_address": "cel-server.local:50051",
    "mapping_file": "/etc/compliance/mappings.yaml"
  }
}
```

# MAPPING FILE FORMAT

The mapping file referenced by `mapping_file` option should be in YAML format:

```yaml
version: "1.0"

# Map OSCAL Rule/Check IDs to CEL rules
mappings:
  # Pod security context check - CIS 1.1.1
  pod-security-context:
    type: stored_rules
    rule_ids:
      - pod-security-context
      
  # Namespace network policy compliance - CIS 4.3.2
  namespace-network-policy-compliance:
    type: stored_rules
    rule_ids:
      - namespace-network-policy-compliance
      
  # Kubeconfig file permissions - CIS 1.1.13
  kubeconfig-file-permissions:
    type: stored_rules
    rule_ids:
      - kubeconfig-file-permissions

# Severity mappings for different check types
severity_mappings:
  security: HIGH
  compliance: CRITICAL
  network-security: HIGH
  pod-security: HIGH
  file-security: CRITICAL
  performance: MEDIUM
  availability: HIGH
  governance: LOW
```

# SEE ALSO

complyctl(1), complyctl-celscanner-plugin(7), cel-go-scanner(1)

See https://github.com/complytime/complyctl for more detailed documentation.

# COPYRIGHT

© 2025 CELScanner Project. c2p-celscanner-manifest.json is released under the terms of the Apache-2.0 license.