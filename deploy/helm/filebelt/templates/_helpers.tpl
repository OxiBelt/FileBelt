{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "filebelt.name" -}}
{{- print "filebelt" -}}
{{- end -}}

{{- define "filebelt.labels" -}}
app.kubernetes.io/name: filebelt
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "filebelt.componentLabels" -}}
{{ include "filebelt.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "filebelt.image" -}}
{{- $root := .root -}}
{{- $image := index $root.Values.images .role -}}
{{- $registry := coalesce $image.registryMirror $root.Values.global.registryMirror $root.Values.global.registry -}}
{{- printf "%s/%s@%s" $registry $image.repository $image.digest -}}
{{- end -}}

{{- define "filebelt.filebeltConfigName" -}}
{{- $configuration := include "filebelt.renderedFilebeltConfiguration" . -}}
{{- printf "%s-config-%s" (include "filebelt.name" . | trunc 42 | trimSuffix "-") ($configuration | sha256sum | trunc 12) -}}
{{- end -}}

{{- define "filebelt.renderedFilebeltConfiguration" -}}
{{- $configuration := tpl .Values.configuration.filebelt . -}}
{{- if .Values.collaboration.enabled -}}
{{- $configuration = replace "[collaboration]\nenabled = false" "[collaboration]\nenabled = true" $configuration -}}
{{- $configuration = replace "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\"]" "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\"]" $configuration -}}
{{- end -}}
{{- if .Values.mounts.enabled -}}
{{- $configuration = replace "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\"]" "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/vfs/io\"]" $configuration -}}
{{- $configuration = replace "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\"]" "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\", \"spiffe://filebelt/vfs/io\"]" $configuration -}}
{{- $configuration = replace "[mounts]\nenabled = false" "[mounts]\nenabled = true" $configuration -}}
{{- $configuration = replace "[mounts.headscale]\nenabled = false" "[mounts.headscale]\nenabled = true" $configuration -}}
{{- $configuration = replace "api_url = \"https://headscale.example.invalid/\"" (printf "api_url = %q" .Values.mounts.headscale.apiUrl) $configuration -}}
{{- $configuration = replace "oidc_issuer = \"https://issuer.example.invalid/\"" (printf "oidc_issuer = %q" .Values.mounts.headscale.oidcIssuer) $configuration -}}
{{- $configuration = replace "sync_seconds = 15" (printf "sync_seconds = %v" .Values.mounts.headscale.syncSeconds) $configuration -}}
{{- end -}}
{{- $configuration -}}
{{- end -}}

{{- define "filebelt.oxibeltConfigName" -}}
{{- $configuration := tpl .Values.configuration.oxibelt . -}}
{{- printf "%s-edge-%s" (include "filebelt.name" . | trunc 44 | trimSuffix "-") ($configuration | sha256sum | trunc 12) -}}
{{- end -}}

{{- define "filebelt.secretGenerationDigest" -}}
{{- $generations := dict -}}
{{- range $name, $secret := .Values.secrets -}}
{{- $_ := set $generations $name $secret.generation -}}
{{- end -}}
{{- toJson $generations | sha256sum -}}
{{- end -}}

{{- define "filebelt.validate" -}}
{{- $renderedFilebeltConfig := include "filebelt.renderedFilebeltConfiguration" . -}}
{{- if not (hasPrefix "version = 5" (trim .Values.configuration.filebelt)) -}}
{{- fail "configuration.filebelt must begin with version = 5" -}}
{{- end -}}
{{- if not (contains "mode = \"kubernetes\"" .Values.configuration.filebelt) -}}
{{- fail "configuration.filebelt must select deployment.mode = kubernetes" -}}
{{- end -}}
{{- if not (contains "strict_unknown_fields = true" .Values.configuration.oxibelt) -}}
{{- fail "configuration.oxibelt must enable strict_unknown_fields" -}}
{{- end -}}
{{- if or (eq (len .Values.networkPolicy.publicIngress.from) 0) (eq (len .Values.networkPolicy.monitoring.from) 0) -}}
{{- fail "networkPolicy publicIngress.from and monitoring.from must not be empty" -}}
{{- end -}}
{{- if or (eq (len .Values.networkPolicy.dns.to) 0) (eq (len .Values.networkPolicy.postgres.to) 0) (eq (len .Values.networkPolicy.oidcGateway.to) 0) -}}
{{- fail "DNS, PostgreSQL, and OIDC gateway peers must not be empty" -}}
{{- end -}}
{{- if .Values.collaboration.enabled -}}
{{- if not (regexMatch "(?m)^\\[collaboration\\]\\s*$[\\s\\S]*^enabled = true\\s*$" $renderedFilebeltConfig) -}}
{{- fail "collaboration.enabled requires configuration.filebelt to enable collaboration" -}}
{{- end -}}
{{- $collaborationSections := regexSplit "(?m)^\\[backend_tls\\.collaboration\\]\\s*$" $renderedFilebeltConfig 2 -}}
{{- if ne (len $collaborationSections) 2 -}}
{{- fail "collaboration.enabled requires an exact backend_tls.collaboration section" -}}
{{- end -}}
{{- $collaborationTls := first (regexSplit "(?m)^\\[" (last $collaborationSections) 2) -}}
{{- if or (not (contains "allowed_client_uri_sans = [\"spiffe://filebelt/web/collaboration\"]" $collaborationTls)) (contains "allowed_client_trust_domains" $collaborationTls) -}}
{{- fail "collaboration backend TLS must permit only the exact FileBelt web SPIFFE identity" -}}
{{- end -}}
{{- $ioSections := regexSplit "(?m)^\\[backend_tls\\.io\\]\\s*$" $renderedFilebeltConfig 2 -}}
{{- if ne (len $ioSections) 2 -}}
{{- fail "collaboration.enabled requires an exact backend_tls.io section" -}}
{{- end -}}
{{- $ioTls := first (regexSplit "(?m)^\\[" (last $ioSections) 2) -}}
{{- $collaborationIoClientUris := "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\"]" -}}
{{- if .Values.mounts.enabled -}}
{{- $collaborationIoClientUris = "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\", \"spiffe://filebelt/vfs/io\"]" -}}
{{- end -}}
{{- if or (not (contains $collaborationIoClientUris $ioTls)) (contains "allowed_client_trust_domains" $ioTls) -}}
{{- fail "I/O backend TLS must permit only the exact web, enabled MCP, and collaboration SPIFFE identities" -}}
{{- end -}}
{{- range $required := list "capability_public_key_file = \"/run/secrets/capability-public-keyset\"" "collaboration_ws = \"0.0.0.0:8085\"" "collaboration_webtransport = \"0.0.0.0:8086\"" "capability_key_generation = 2" "io_url = \"https://filebelt-worker-io:8081/\"" "client_certificate_chain_file = \"/run/secrets/collaboration-io-client-tls/tls.crt\"" "client_private_key_file = \"/run/secrets/collaboration-io-client-tls/tls.key\"" "server_ca_file = \"/run/secrets/collaboration-io-client-tls/server-ca.crt\"" -}}
{{- if not (contains $required $renderedFilebeltConfig) -}}
{{- fail (printf "collaboration.enabled requires configuration.filebelt setting %s" $required) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if .Values.mcp.enabled -}}
{{- if not .Values.networkPolicy.mcpGateway.enabled -}}
{{- fail "mcp.enabled requires networkPolicy.mcpGateway.enabled" -}}
{{- end -}}
{{- if eq (len .Values.networkPolicy.mcpGateway.to) 0 -}}
{{- fail "mcp.enabled requires a nonempty MCP gateway peer allowlist" -}}
{{- end -}}
{{- if not (regexMatch "(?m)^\\[mcp\\]\\s*$[\\s\\S]*^enabled = true\\s*$" $renderedFilebeltConfig) -}}
{{- fail "mcp.enabled requires configuration.filebelt to enable the MCP broker" -}}
{{- end -}}
{{- $brokerSections := regexSplit "(?m)^\\[backend_tls\\.mcp_broker\\]\\s*$" $renderedFilebeltConfig 2 -}}
{{- if ne (len $brokerSections) 2 -}}
{{- fail "mcp.enabled requires an exact backend_tls.mcp_broker section" -}}
{{- end -}}
{{- $brokerTls := first (regexSplit "(?m)^\\[" (last $brokerSections) 2) -}}
{{- $brokerClientUris := "allowed_client_uri_sans = [\"spiffe://filebelt/api/mcp\"]" -}}
{{- if .Values.mcp.runners.enabled -}}
{{- $brokerClientUris = "allowed_client_uri_sans = [\"spiffe://filebelt/api/mcp\", \"spiffe://filebelt/runner/mcp\"]" -}}
{{- end -}}
{{- if or (not (contains $brokerClientUris $brokerTls)) (contains "allowed_client_trust_domains" $brokerTls) -}}
{{- fail "MCP broker backend TLS must permit only the exact FileBelt API and enabled runner SPIFFE identities" -}}
{{- end -}}
{{- $ioSections := regexSplit "(?m)^\\[backend_tls\\.io\\]\\s*$" $renderedFilebeltConfig 2 -}}
{{- if ne (len $ioSections) 2 -}}
{{- fail "mcp.enabled requires an exact backend_tls.io section" -}}
{{- end -}}
{{- $ioTls := first (regexSplit "(?m)^\\[" (last $ioSections) 2) -}}
{{- $mcpIoClientUris := "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\"]" -}}
{{- if .Values.mounts.enabled -}}
{{- $mcpIoClientUris = "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/vfs/io\"]" -}}
{{- end -}}
{{- if or (not (contains $mcpIoClientUris $ioTls)) (contains "allowed_client_trust_domains" $ioTls) -}}
{{- fail "I/O backend TLS must permit only the exact FileBelt web and MCP broker SPIFFE identities" -}}
{{- end -}}
{{- range $required := list "io_url = \"https://filebelt-worker-io:8081/\"" "client_certificate_chain_file = \"/run/secrets/mcp-backend-tls/tls.crt\"" "client_private_key_file = \"/run/secrets/mcp-backend-tls/tls.key\"" "server_ca_file = \"/run/secrets/mcp-backend-tls/server-ca.crt\"" -}}
{{- if not (contains $required $renderedFilebeltConfig) -}}
{{- fail (printf "mcp.enabled requires configuration.filebelt attachment setting %s" $required) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if .Values.mcp.runners.enabled -}}
{{- if eq .Values.mcp.runners.namespace .Release.Namespace -}}
{{- fail "mcp.runners.namespace must be a dedicated namespace separate from the FileBelt release namespace" -}}
{{- end -}}
{{- if not (contains "mcp_runner_relay = \"0.0.0.0:8084\"" $renderedFilebeltConfig) -}}
{{- fail "mcp.runners.enabled requires configuration.filebelt listener mcp_runner_relay on 0.0.0.0:8084" -}}
{{- end -}}
{{- if not .Values.networkPolicy.kubernetesApi.enabled -}}
{{- fail "mcp.runners.enabled requires networkPolicy.kubernetesApi.enabled" -}}
{{- end -}}
{{- if eq (len .Values.networkPolicy.kubernetesApi.to) 0 -}}
{{- fail "mcp.runners.enabled requires an exact Kubernetes API peer allowlist" -}}
{{- end -}}
{{- $runnerImage := include "filebelt.image" (dict "root" . "role" "filebelt-mcp-runner") -}}
{{- if not (contains (printf "runner_image = %q" $runnerImage) $renderedFilebeltConfig) -}}
{{- fail "mcp.runners.enabled requires configuration.filebelt runner_image to match the chart digest" -}}
{{- end -}}
{{- $runnerSections := regexSplit "(?m)^\\[mcp\\.runners\\]\\s*$" $renderedFilebeltConfig 2 -}}
{{- if ne (len $runnerSections) 2 -}}
{{- fail "mcp.runners.enabled requires an exact mcp.runners configuration section" -}}
{{- end -}}
{{- $runnerConfig := first (regexSplit "(?m)^\\[" (last $runnerSections) 2) -}}
{{- if not (contains (printf "namespace = %q" .Values.mcp.runners.namespace) $runnerConfig) -}}
{{- fail "mcp.runners.enabled requires configuration.filebelt namespace to match mcp.runners.namespace" -}}
{{- end -}}
{{- $controllerUrl := printf "https://%s-controller.%s.svc:8083/" (include "filebelt.name" .) .Release.Namespace -}}
{{- if not (contains (printf "controller_url = %q" $controllerUrl) $renderedFilebeltConfig) -}}
{{- fail "mcp.runners.enabled requires configuration.filebelt controller_url to match the chart Service" -}}
{{- end -}}
{{- $controllerSections := regexSplit "(?m)^\\[backend_tls\\.controller\\]\\s*$" $renderedFilebeltConfig 2 -}}
{{- if ne (len $controllerSections) 2 -}}
{{- fail "mcp.runners.enabled requires an exact backend_tls.controller section" -}}
{{- end -}}
{{- $controllerTls := first (regexSplit "(?m)^\\[" (last $controllerSections) 2) -}}
{{- if or (not (contains "allowed_client_uri_sans = [\"spiffe://filebelt/mcp-broker/controller\"]" $controllerTls)) (contains "allowed_client_trust_domains" $controllerTls) -}}
{{- fail "controller backend TLS must permit only the exact FileBelt MCP broker SPIFFE identity" -}}
{{- end -}}
{{- range $required := list "catalog_file = \"/etc/filebelt/mcp/catalog/catalog.json\"" "trusted_root_file = \"/etc/filebelt/mcp/trust/trusted-root.json\"" "bundle_directory = \"/etc/filebelt/mcp/bundles\"" "controller_client_certificate_chain_file = \"/run/secrets/controller-client-tls/tls.crt\"" "controller_client_private_key_file = \"/run/secrets/controller-client-tls/tls.key\"" "controller_server_ca_file = \"/run/secrets/controller-client-tls/server-ca.crt\"" -}}
{{- if not (contains $required $renderedFilebeltConfig) -}}
{{- fail (printf "mcp.runners.enabled requires configuration.filebelt setting %s" $required) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if .Values.mounts.enabled -}}
{{- if not .Values.mounts.tailnet.kernelNetworking -}}
{{- fail "mounts.enabled requires tailnet.kernelNetworking=true for direct SMB/FTPS reachability" -}}
{{- end -}}
{{- if or (eq (len .Values.networkPolicy.headscale.to) 0) (eq (len .Values.networkPolicy.mountIngress.from) 0) -}}
{{- fail "mounts.enabled requires exact Headscale egress and mount ingress peer allowlists" -}}
{{- end -}}
{{- range $required := list "[mounts]" "enabled = true" "database_url_file = \"/run/secrets/mount-database-url\"" "vault_keyring_file = \"/run/secrets/mount-vault-keyring.json\"" "capability_private_key_file = \"/run/secrets/mount-capability-private-key\"" "capability_key_generation = 3" "io_url = \"https://filebelt-worker-io:8081/\"" "io_client_certificate_chain_file = \"/run/secrets/vfs-io-client-tls/tls.crt\"" "management_url = \"https://filebelt-vfs-management:8088/\"" "[backend_tls.vfs]" "[backend_tls.vfs_management]" -}}
{{- if not (contains $required $renderedFilebeltConfig) -}}
{{- fail (printf "mounts.enabled requires configuration.filebelt setting %s" $required) -}}
{{- end -}}
{{- end -}}
{{- range $workload := list .Values.mounts.smb .Values.mounts.ftpFtps -}}
{{- if eq $workload.tailstateClaim "" -}}
{{- fail "mounts.enabled requires an operator-provided RWO tailstate claim for every workload" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $networkJson := toJson .Values.networkPolicy -}}
{{- if regexMatch "\\\"cidr\\\":\\\"[^\\\"]+/0\\\"" $networkJson -}}
{{- fail "networkPolicy must not permit an unrestricted Internet CIDR" -}}
{{- end -}}
{{- if and (ne .Values.operation.type "none") (eq .Values.operation.operationId "") -}}
{{- fail "operation.operationId is required when operation.type is not none" -}}
{{- end -}}
{{- if and (eq .Values.operation.type "storage-scrub-start") (eq .Values.operation.payloadId "") (eq .Values.operation.tenantSlugConfirmation "") -}}
{{- fail "full storage-scrub-start requires operation.tenantSlugConfirmation" -}}
{{- end -}}
{{- if and (eq .Values.operation.type "storage-scrub-start") (ne .Values.operation.payloadId "") (ne .Values.operation.tenantSlugConfirmation "") -}}
{{- fail "targeted storage-scrub-start must not include operation.tenantSlugConfirmation" -}}
{{- end -}}
{{- if and (has .Values.operation.type (list "recovery-checkpoint" "recovery-verify")) (not .Values.deployment.quiesced) -}}
{{- fail "recovery operations require deployment.quiesced=true" -}}
{{- end -}}
{{- if and (eq .Values.operation.type "recovery-verify") (eq .Values.operation.checkpoint.secretName "") -}}
{{- fail "operation.checkpoint.secretName is required for recovery-verify" -}}
{{- end -}}
{{- if and .Values.monitoring.serviceMonitor.enabled (not (.Capabilities.APIVersions.Has "monitoring.coreos.com/v1/ServiceMonitor")) -}}
{{- fail "monitoring.serviceMonitor.enabled requires the monitoring.coreos.com/v1 ServiceMonitor CRD" -}}
{{- end -}}
{{- if and .Values.monitoring.prometheusRule.enabled (not (.Capabilities.APIVersions.Has "monitoring.coreos.com/v1/PrometheusRule")) -}}
{{- fail "monitoring.prometheusRule.enabled requires the monitoring.coreos.com/v1 PrometheusRule CRD" -}}
{{- end -}}
{{- end -}}

{{- define "filebelt.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.global.runAsUser }}
runAsGroup: {{ .Values.global.runAsGroup }}
fsGroup: {{ .Values.global.runAsGroup }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
supplementalGroups: [{{ .Values.global.runAsGroup }}]
{{- end -}}

{{- define "filebelt.containerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop: ["ALL"]
privileged: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: {{ .Values.global.runAsUser }}
runAsGroup: {{ .Values.global.runAsGroup }}
{{- end -}}

{{- define "filebelt.tailscaledSecurityContext" -}}
# Kernel-mode tailscaled needs only NET_ADMIN and the projected /dev/net/tun
# character device; it deliberately remains non-privileged and rootfs read-only.
allowPrivilegeEscalation: false
capabilities:
  drop: ["ALL"]
  add: ["NET_ADMIN"]
privileged: false
readOnlyRootFilesystem: true
runAsNonRoot: false
runAsUser: 0
runAsGroup: 0
{{- end -}}

{{- define "filebelt.filebeltConfigVolume" -}}
- name: filebelt-config
  configMap:
    name: {{ include "filebelt.filebeltConfigName" . }}
    defaultMode: 0444
    items:
      - key: filebelt.toml
        path: filebelt.toml
{{- end -}}

{{- define "filebelt.tmpVolume" -}}
- name: tmp
  emptyDir:
    sizeLimit: 32Mi
{{- end -}}
