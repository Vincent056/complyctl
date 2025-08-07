mkdir -p ./bin
go build -mod=vendor -o ./bin/ -ldflags="-X github.com/complytime/complyctl/internal/version.version="" -X github.com/complytime/complyctl/internal/version.gitTreeState=dirty -X github.com/complytime/complyctl/internal/version.commit="19401b8" -X github.com/complytime/complyctl/internal/version.buildDate="2025-08-07T08:16:40Z"" ./cmd/...
INFO Assessment plan written to complytime/assessment-plan.json

INFO Searching for plugins in /usr/libexec/complytime/plugins
INFO celscanner: configuring client automatic mTLS
INFO celscanner-plugin: Starting CELScanner plugin @module=celscanner-plugin timestamp=2025-08-07T01:16:42.608-0700
INFO celscanner-plugin: configuring server automatic mTLS @module=celscanner-plugin timestamp=2025-08-07T01:16:42.608-0700
INFO celscanner-plugin: Configuring CELScanner plugin @module=celscanner-plugin timestamp=2025-08-07T01:16:42.616-0700
INFO celscanner-plugin: Kubernetes clients configured successfully @module=celscanner-plugin timestamp=2025-08-07T01:16:42.617-0700
INFO celscanner-plugin: Loading rules from YAML store @module=celscanner-plugin file_count=3 path=complytime/rules timestamp=2025-08-07T01:16:42.617-0700
INFO celscanner-plugin: Loaded rules @module=celscanner-plugin total=3 timestamp=2025-08-07T01:16:42.617-0700
INFO celscanner-plugin: Rule store initialized @module=celscanner-plugin path=complytime/rules rule_count=3 timestamp=2025-08-07T01:16:42.617-0700
INFO Successfully loaded 1 plugin(s).
INFO celscanner-plugin: Getting CEL scan results @module=celscanner-plugin timestamp=2025-08-07T01:16:42.617-0700
INFO celscanner-plugin: Kubernetes fetching enabled with live cluster connection @module=celscanner-plugin timestamp=2025-08-07T01:16:42.617-0700
INFO celscanner-plugin: Filesystem fetching enabled @module=celscanner-plugin timestamp=2025-08-07T01:16:42.617-0700
INFO celscanner-plugin: Fetching resources from API server @module=celscanner-plugin timestamp=2025-08-07T01:16:42.617-0700
INFO celscanner-plugin: Fetching resources from API server @module=celscanner-plugin timestamp=2025-08-07T01:16:43.581-0700
INFO celscanner-plugin: Fetching resources from API server @module=celscanner-plugin timestamp=2025-08-07T01:16:43.614-0700
INFO celscanner-plugin: kubeconfig-file-permissions: true @module=celscanner-plugin timestamp=2025-08-07T01:16:43.615-0700
INFO celscanner-plugin: Completed CEL scan @module=celscanner-plugin observations=3 timestamp=2025-08-07T01:16:43.616-0700
2025-08-07T01:16:43.616-0700 [INFO]  reporter: generating assessments results for plan file://complytime/assessment-plan.json
2025-08-07T01:16:43.616-0700 [INFO]  reporter: generated finding for rule namespace-network-policy-compliance for subject production-k8s-cluster
2025-08-07T01:16:43.616-0700 [INFO]  reporter: generated finding for rule namespace-network-policy-compliance for subject production-k8s-cluster
2025-08-07T01:16:43.616-0700 [INFO]  reporter: generated finding for rule pod-security-context for subject production-k8s-cluster
2025-08-07T01:16:43.616-0700 [INFO]  reporter: generated finding for rule pod-security-context for subject production-k8s-cluster
INFO The assessment results in JSON were successfully written to complytime/assessment-results.json.
INFO No assessment result in markdown will be generated.
INFO celscanner: plugin process exited plugin=/usr/libexec/complytime/plugins/celscanner-plugin id=2384422
