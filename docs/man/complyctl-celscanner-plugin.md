% COMPLYCTL_CELSCANNER-PLUGIN(7) Complyctl CELScanner Plugin
% Vincent056 <wenshen@redhat.com>
% August 2025

# NAME

complyctl-celscanner-plugin - a plugin which extends the complyctl capabilities to use CEL (Common Expression Language) for compliance validation.

# DESCRIPTION

The plugin is not meant to be executed directly, it communicates with complyctl via gRPC. It has configurable options that can be configured via a manifest file, complyctl processes the manifest file and sends the configuration values to the plugin.

When the plugin receives the **scan** command from complyctl, it loads CEL rules from YAML files in the rules directory, maps OSCAL Rule/Check IDs to these rules using a mapping configuration, evaluates the CEL rules against the target environment using multiple input sources (Kubernetes, filesystem, HTTP, system), and returns the observations to complyctl based on CEL evaluation results.

The plugin supports both local evaluation and remote evaluation via CEL RPC Server. For security reasons, system command execution is limited to service status checks only.

# FILES

**/usr/share/complytime/plugins/celscanner-plugin**
Default plugin binary location.

**/etc/complytime/config.d/c2p-celscanner-manifest.json**
Optional drop-in manifest file with customized plugin configurations.

**~/complytime/rules/**
Directory containing CEL rule definitions in YAML format.

**~/complytime/mappings.yaml**
Mapping configuration file that links OSCAL Rule/Check IDs to CEL rules.

**~/complytime/celscanner/results/cel-results.yaml**
Scan results file (assuming default workspace).

# FEATURES

**Input Sources:**
- Kubernetes: Query and validate Kubernetes resources (pods, deployments, services, etc.)
- Filesystem: Check file contents, permissions, and properties
- HTTP: Make API calls for validation
- System: Limited to service status checks only (systemctl, getenforce) for security

**Execution Modes:**
- Local Mode: Direct CEL evaluation in the plugin process
- RPC Mode: Remote evaluation via CEL RPC Server

**Rule Management:**
- YAML-based rule storage system
- One-to-many mapping: One OSCAL RuleSet can map to multiple CEL rules
- Custom mapping configuration support
- Hierarchical lookup by RuleSet ID or Check ID

# EXAMPLES

The following steps demonstrate a typical workflow using the CELScanner plugin for Kubernetes compliance validation.

Step 1: Create a manifest file with plugin configuration

$ cat > manifest.yaml <<EOF
assessment-plan: assessment-plan.json
plugins:
  - name: celscanner-plugin
    config:
      workspace: ./workspace
      enable_kubernetes: true
      target_name: production-cluster
      include_namespaces: default,production
      mapping_file: mappings.yaml
EOF

Step 2: Scan the environment with the rules

$ complyctl scan -m manifest.yaml

This loads CEL rules from the rule store based on the mapping configuration and evaluates them.

The scan results are saved to ~/complytime/celscanner/results/cel-results.yaml.

Step 3: Generate a compliance report

$ complyctl report -m manifest.yaml

# RULE MAPPING

The plugin uses a flexible mapping system to convert OSCAL rules to CEL expressions. Create a mapping file:

$ cat > mappings.yaml <<EOF
version: "1.0"
mappings:
  # Map OSCAL Rule/Check IDs to stored rules
  pod-security-context:
    type: stored_rules
    rule_ids:
      - pod-security-context
      
  namespace-network-policy-compliance:
    type: stored_rules
    rule_ids:
      - namespace-network-policy-compliance
  
  kubeconfig-file-permissions:
    type: stored_rules
    rule_ids:
      - kubeconfig-file-permissions
      
  sshd-service:
    type: stored_rules
    rule_ids:
      - sshd-service-enabled
      - sshd-service-running
EOF

# SYSTEM CHECKS

For security, system commands are restricted to:
- Service status: `systemctl is-active <service>`
- Service enabled: `systemctl is-enabled <service>`
- SELinux status: `getenforce`

Example:
```yaml
sshd-service-enabled:
  expression: 'service.success && contains(service.output, "enabled")'
  inputs:
    - name: service
      type: system
      command: systemctl
      args: [is-enabled, sshd]
```

# SEE ALSO

complyctl(1), c2p-celscanner-manifest.json(5), cel-go-scanner(1)

See the upstream projects at https://github.com/complytime/complyctl and https://github.com/Vincent056/celscanner for more detailed documentation.

# COPYRIGHT

© 2024 CELScanner Project. complyctl-celscanner-plugin is released under the terms of the Apache-2.0 license.