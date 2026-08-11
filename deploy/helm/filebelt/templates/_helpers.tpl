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
{{- $mountsEnabled := or .Values.mounts.smb.enabled .Values.mounts.ftpFtps.enabled .Values.mounts.nfs.enabled -}}
{{- $headscaleRequired := or .Values.mounts.smb.enabled .Values.mounts.ftpFtps.enabled -}}
{{- if .Values.collaboration.enabled -}}
{{- $configuration = replace "[collaboration]\nenabled = false" "[collaboration]\nenabled = true" $configuration -}}
{{- $configuration = printf "%s\n\n[keys.api_collaboration_grant]\nprivate_key_file = \"/run/secrets/api-collaboration-grant-capability-private-key\"\npublic_keyset_file = \"/run/secrets/api-collaboration-grant-capability-public-keyset\"\ncurrent_generation = 1\n\n[collaboration.capability_signing]\nprivate_key_file = \"/run/secrets/collaboration-storage-capability-private-key\"\npublic_keyset_file = \"/run/secrets/collaboration-storage-capability-public-keyset\"\ncurrent_generation = 1" $configuration -}}
{{- $configuration = replace "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\"]" "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\"]" $configuration -}}
{{- if .Values.collaboration.webtransport.enabled -}}
{{- $configuration = replace "webtransport_enabled = false" "webtransport_enabled = true\nwebtransport_endpoint = \"https://filebelt.example.invalid/collaboration/v1/wt\"\nwebtransport_idle_seconds = 75\nwebtransport_drain_seconds = 300" $configuration -}}
{{- end -}}
{{- end -}}
{{- if .Values.mcp.enabled -}}
{{- $configuration = printf "%s\n\n[keys.api_mcp_delegation]\nprivate_key_file = \"/run/secrets/api-mcp-delegation-capability-private-key\"\npublic_keyset_file = \"/run/secrets/api-mcp-delegation-capability-public-keyset\"\ncurrent_generation = 1" $configuration -}}
{{- end -}}
{{- if $mountsEnabled -}}
{{- $configuration = replace "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\"]" "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/vfs/io\"]" $configuration -}}
{{- $configuration = replace "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\"]" "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\", \"spiffe://filebelt/vfs/io\"]" $configuration -}}
{{- $configuration = printf "%s\n\n[mounts.capability_signing]\nprivate_key_file = \"/run/secrets/mount-storage-capability-private-key\"\npublic_keyset_file = \"/run/secrets/mount-storage-capability-public-keyset\"\ncurrent_generation = 1" $configuration -}}
{{- $gatewayUriSans := list -}}
{{- if .Values.mounts.smb.enabled -}}
{{- $configuration = replace "[mounts.smb]\nenabled = false" "[mounts.smb]\nenabled = true" $configuration -}}
{{- $gatewayUriSans = append $gatewayUriSans "spiffe://filebelt/smb-gateway/vfs" -}}
{{- if ne .Values.mounts.smb.previousGatewayUriSan "" -}}
{{- $configuration = replace "gateway_uri_san = \"spiffe://filebelt/smb-gateway/vfs\"" (printf "gateway_uri_san = \"spiffe://filebelt/smb-gateway/vfs\"\nprevious_gateway_uri_san = %q" .Values.mounts.smb.previousGatewayUriSan) $configuration -}}
{{- $gatewayUriSans = append $gatewayUriSans .Values.mounts.smb.previousGatewayUriSan -}}
{{- end -}}
{{- end -}}
{{- if .Values.mounts.ftpFtps.enabled -}}
{{- $configuration = replace "[mounts.ftp_ftps]\nenabled = false" "[mounts.ftp_ftps]\nenabled = true" $configuration -}}
{{- $gatewayUriSans = append $gatewayUriSans "spiffe://filebelt/ftp-ftps-gateway/vfs" -}}
{{- if ne .Values.mounts.ftpFtps.previousGatewayUriSan "" -}}
{{- $configuration = replace "gateway_uri_san = \"spiffe://filebelt/ftp-ftps-gateway/vfs\"" (printf "gateway_uri_san = \"spiffe://filebelt/ftp-ftps-gateway/vfs\"\nprevious_gateway_uri_san = %q" .Values.mounts.ftpFtps.previousGatewayUriSan) $configuration -}}
{{- $gatewayUriSans = append $gatewayUriSans .Values.mounts.ftpFtps.previousGatewayUriSan -}}
{{- end -}}
{{- end -}}
{{- if .Values.mounts.nfs.enabled -}}
{{- $nfsConfig := printf "[mounts.nfs]\nenabled = true\ngateway_uri_san = \"spiffe://filebelt/nfs-gateway/vfs\"\nrealm = %q\nidmap_domain = %q\nhandle_keyring_file = \"/run/secrets/nfs-handle-keyring.json\"\nhandle_key_generation = %v\ngrace_seconds = %v" .Values.mounts.nfs.realm .Values.mounts.nfs.idmapDomain .Values.mounts.nfs.handleKeyGeneration .Values.mounts.nfs.graceSeconds -}}
{{- if ne .Values.mounts.nfs.previousGatewayUriSan "" -}}
{{- $nfsConfig = printf "%s\nprevious_gateway_uri_san = %q" $nfsConfig .Values.mounts.nfs.previousGatewayUriSan -}}
{{- end -}}
{{- $configuration = replace "[mounts.nfs]\nenabled = false\ngateway_uri_san = \"spiffe://filebelt/nfs-gateway/vfs\"\ngrace_seconds = 90" $nfsConfig $configuration -}}
{{- $gatewayUriSans = append $gatewayUriSans "spiffe://filebelt/nfs-gateway/vfs" -}}
{{- if ne .Values.mounts.nfs.previousGatewayUriSan "" -}}
{{- $gatewayUriSans = append $gatewayUriSans .Values.mounts.nfs.previousGatewayUriSan -}}
{{- end -}}
{{- end -}}
{{- $quotedGatewayUriSans := list -}}
{{- range $gatewayUriSan := $gatewayUriSans -}}
{{- $quotedGatewayUriSans = append $quotedGatewayUriSans (printf "%q" $gatewayUriSan) -}}
{{- end -}}
{{- $configuration = printf "%s\n\n[backend_tls.vfs]\ncertificate_chain_file = \"/run/secrets/vfs-server-tls/tls.crt\"\nprivate_key_file = \"/run/secrets/vfs-server-tls/tls.key\"\nclient_ca_file = \"/run/secrets/vfs-server-tls/client-ca.crt\"\nallowed_client_uri_sans = [%s]\n\n[backend_tls.vfs_management]\ncertificate_chain_file = \"/run/secrets/vfs-management-server-tls/tls.crt\"\nprivate_key_file = \"/run/secrets/vfs-management-server-tls/tls.key\"\nclient_ca_file = \"/run/secrets/vfs-management-server-tls/client-ca.crt\"\nallowed_client_uri_sans = [\"spiffe://filebelt/api/vfs-management\"]" $configuration (join ", " $quotedGatewayUriSans) -}}
{{- end -}}
{{- if $headscaleRequired -}}
{{- $configuration = replace "[mounts.headscale]\nenabled = false" "[mounts.headscale]\nenabled = true" $configuration -}}
{{- $configuration = replace "api_url = \"https://headscale.example.invalid/\"" (printf "api_url = %q" .Values.mounts.headscale.apiUrl) $configuration -}}
{{- $configuration = replace "oidc_issuer = \"https://issuer.example.invalid/\"" (printf "oidc_issuer = %q" .Values.mounts.headscale.oidcIssuer) $configuration -}}
{{- $configuration = replace "sync_seconds = 15" (printf "sync_seconds = %v" .Values.mounts.headscale.syncSeconds) $configuration -}}
{{- end -}}
{{- if .Values.documents.enabled -}}
{{- $documentConfig := printf "[documents]\nenabled = true\nprovider_id = \"onlyoffice-community-9-4\"\ndatabase_url_file = \"/run/secrets/document-database-url\"\nurl = \"https://filebelt-document:8089/\"\nlaunch_action = %q\nprovider_origin = %q\nclient_certificate_chain_file = \"/run/secrets/document-api-client-tls/tls.crt\"\nclient_private_key_file = \"/run/secrets/document-api-client-tls/tls.key\"\nserver_ca_file = \"/run/secrets/document-api-client-tls/server-ca.crt\"\nmax_active_tabs = 20\nmax_document_bytes = 104857600\ngeneration_recheck_seconds = 60\n\n[documents.capability_signing]\nprivate_key_file = \"/run/secrets/document-storage-capability-private-key\"\npublic_keyset_file = \"/run/secrets/document-storage-capability-public-keyset\"\ncurrent_generation = 1" .Values.documents.launchAction .Values.documents.providerOrigin -}}
{{- $configuration = replace "[documents]\nenabled = false" $documentConfig $configuration -}}
{{- $configuration = printf "%s\n\n[backend_tls.document]\ncertificate_chain_file = \"/run/secrets/document-api-server-tls/tls.crt\"\nprivate_key_file = \"/run/secrets/document-api-server-tls/tls.key\"\nclient_ca_file = \"/run/secrets/document-api-server-tls/client-ca.crt\"\nallowed_client_uri_sans = [\"spiffe://filebelt/api/document\"]\n\n[backend_tls.document_adapter]\ncertificate_chain_file = \"/run/secrets/document-adapter-server-tls/tls.crt\"\nprivate_key_file = \"/run/secrets/document-adapter-server-tls/tls.key\"\nclient_ca_file = \"/run/secrets/document-adapter-server-tls/client-ca.crt\"\nallowed_client_uri_sans = [\"spiffe://filebelt/onlyoffice-adapter/document\"]" $configuration -}}
{{- range $current := list
    "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\"]"
    "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\"]"
    "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/vfs/io\"]"
    "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\", \"spiffe://filebelt/vfs/io\"]" -}}
{{- if contains $current $configuration -}}
{{- $withAdapter := replace "]" ", \"spiffe://filebelt/onlyoffice-adapter/io\"]" $current -}}
{{- $configuration = replace $current $withAdapter $configuration -}}
{{- end -}}
{{- end -}}
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
{{- $mountsEnabled := or .Values.mounts.smb.enabled .Values.mounts.ftpFtps.enabled .Values.mounts.nfs.enabled -}}
{{- $headscaleRequired := or .Values.mounts.smb.enabled .Values.mounts.ftpFtps.enabled -}}
{{- if not (hasPrefix "version = 8" (trim .Values.configuration.filebelt)) -}}
{{- fail "configuration.filebelt must begin with version = 8" -}}
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
{{- if $mountsEnabled -}}
{{- $collaborationIoClientUris = "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/collaboration/io\", \"spiffe://filebelt/vfs/io\"]" -}}
{{- end -}}
{{- if .Values.documents.enabled -}}
{{- $collaborationIoClientUris = replace "]" ", \"spiffe://filebelt/onlyoffice-adapter/io\"]" $collaborationIoClientUris -}}
{{- end -}}
{{- if or (not (contains $collaborationIoClientUris $ioTls)) (contains "allowed_client_trust_domains" $ioTls) -}}
{{- fail "I/O backend TLS must permit only the exact web, enabled MCP, and collaboration SPIFFE identities" -}}
{{- end -}}
{{- range $required := list "[keys.api_collaboration_grant]" "[collaboration.capability_signing]" "collaboration_ws = \"0.0.0.0:8085\"" "collaboration_webtransport = \"0.0.0.0:8086\"" "io_url = \"https://filebelt-worker-io:8081/\"" "client_certificate_chain_file = \"/run/secrets/collaboration-io-client-tls/tls.crt\"" "client_private_key_file = \"/run/secrets/collaboration-io-client-tls/tls.key\"" "server_ca_file = \"/run/secrets/collaboration-io-client-tls/server-ca.crt\"" -}}
{{- if not (contains $required $renderedFilebeltConfig) -}}
{{- fail (printf "collaboration.enabled requires configuration.filebelt setting %s" $required) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.collaboration.webtransport.enabled (not (contains "webtransport_enabled = true" $renderedFilebeltConfig)) -}}
{{- fail "collaboration.webtransport.enabled requires the reviewed WebTransport runtime configuration" -}}
{{- end -}}
{{- if and .Values.collaboration.webtransport.enabled (not .Values.collaboration.enabled) -}}
{{- fail "collaboration.webtransport.enabled requires collaboration.enabled" -}}
{{- end -}}
{{- end -}}
{{- if .Values.documents.enabled -}}
{{- $editorLaunch := urlParse .Values.documents.launchAction -}}
{{- $editorHost := first (splitList ":" $editorLaunch.host) -}}
{{- $providerOrigin := urlParse .Values.documents.providerOrigin -}}
{{- $providerHost := first (splitList ":" $providerOrigin.host) -}}
{{- if or (eq $editorHost "filebelt.example.invalid") (eq $providerHost "filebelt.example.invalid") (eq $editorHost $providerHost) -}}
{{- fail "documents.launchAction, the public FileBelt host, and documents.providerOrigin must use pairwise distinct hostnames" -}}
{{- end -}}
{{- if not (regexMatch "(?m)^\\[documents\\]\\s*$[\\s\\S]*^enabled = true\\s*$" $renderedFilebeltConfig) -}}
{{- fail "documents.enabled requires configuration.filebelt to enable document sessions" -}}
{{- end -}}
{{- range $section := list "document" "document_adapter" -}}
{{- $sections := regexSplit (printf "(?m)^\\[backend_tls\\.%s\\]\\s*$" $section) $renderedFilebeltConfig 2 -}}
{{- if ne (len $sections) 2 -}}
{{- fail (printf "documents.enabled requires an exact backend_tls.%s section" $section) -}}
{{- end -}}
{{- $tls := first (regexSplit "(?m)^\\[" (last $sections) 2) -}}
{{- $identity := ternary "spiffe://filebelt/api/document" "spiffe://filebelt/onlyoffice-adapter/document" (eq $section "document") -}}
{{- if or (not (contains (printf "allowed_client_uri_sans = [%q]" $identity) $tls)) (contains "allowed_client_trust_domains" $tls) -}}
{{- fail (printf "backend_tls.%s must permit only its exact document client SPIFFE identity" $section) -}}
{{- end -}}
{{- end -}}
{{- range $required := list "document = \"0.0.0.0:8089\"" "document_adapter = \"0.0.0.0:8090\"" "url = \"https://filebelt-document:8089/\"" (printf "launch_action = %q" .Values.documents.launchAction) (printf "provider_origin = %q" .Values.documents.providerOrigin) "[documents.capability_signing]" "max_active_tabs = 20" "max_document_bytes = 104857600" "generation_recheck_seconds = 60" -}}
{{- if not (contains $required $renderedFilebeltConfig) -}}
{{- fail (printf "documents.enabled requires configuration.filebelt setting %s" $required) -}}
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
{{- if $mountsEnabled -}}
{{- $mcpIoClientUris = "allowed_client_uri_sans = [\"spiffe://filebelt/web/io\", \"spiffe://filebelt/mcp-broker/io\", \"spiffe://filebelt/vfs/io\"]" -}}
{{- end -}}
{{- if .Values.documents.enabled -}}
{{- $mcpIoClientUris = replace "]" ", \"spiffe://filebelt/onlyoffice-adapter/io\"]" $mcpIoClientUris -}}
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
{{- if and (not .Values.mounts.smb.enabled) (ne .Values.mounts.smb.previousGatewayUriSan "") -}}
{{- fail "disabled SMB must not carry a previous gateway URI SAN" -}}
{{- end -}}
{{- if and (not .Values.mounts.ftpFtps.enabled) (ne .Values.mounts.ftpFtps.previousGatewayUriSan "") -}}
{{- fail "disabled FTP/FTPS must not carry a previous gateway URI SAN" -}}
{{- end -}}
{{- if not .Values.mounts.nfs.enabled -}}
{{- if or (ne .Values.mounts.nfs.previousGatewayUriSan "") (ne .Values.mounts.nfs.realm "") (ne .Values.mounts.nfs.idmapDomain "") (ne .Values.mounts.nfs.tailstateClaim "") (ne .Values.mounts.nfs.recoveryClaim "") (ne (int .Values.mounts.nfs.handleKeyGeneration) 1) (ne (int .Values.mounts.nfs.graceSeconds) 90) -}}
{{- fail "disabled NFS must not carry a previous gateway URI SAN or authority overrides" -}}
{{- end -}}
{{- end -}}
{{- $currentGatewayUriSans := list "spiffe://filebelt/smb-gateway/vfs" "spiffe://filebelt/ftp-ftps-gateway/vfs" "spiffe://filebelt/nfs-gateway/vfs" -}}
{{- $previousGatewayUriSans := list -}}
{{- range $protocol := list .Values.mounts.smb .Values.mounts.ftpFtps .Values.mounts.nfs -}}
{{- if and $protocol.enabled (ne $protocol.previousGatewayUriSan "") -}}
{{- if has $protocol.previousGatewayUriSan $currentGatewayUriSans -}}
{{- fail "a previous gateway URI SAN must not equal any current protocol identity" -}}
{{- end -}}
{{- $previousGatewayUriSans = append $previousGatewayUriSans $protocol.previousGatewayUriSan -}}
{{- end -}}
{{- end -}}
{{- if ne (len $previousGatewayUriSans) (len (uniq $previousGatewayUriSans)) -}}
{{- fail "previous gateway URI SANs must be pairwise distinct" -}}
{{- end -}}
{{- if $mountsEnabled -}}
{{- if not .Values.mounts.tailnet.kernelNetworking -}}
{{- fail "an enabled mount protocol requires tailnet.kernelNetworking=true" -}}
{{- end -}}
{{- if or (eq (len .Values.networkPolicy.headscale.to) 0) (eq (len .Values.networkPolicy.mountIngress.from) 0) -}}
{{- fail "an enabled mount protocol requires exact tailnet-control egress and mount ingress peer allowlists" -}}
{{- end -}}
{{- range $required := list "[mounts]" "database_url_file = \"/run/secrets/mount-database-url\"" "vault_keyring_file = \"/run/secrets/mount-vault-keyring.json\"" "[mounts.capability_signing]" "io_url = \"https://filebelt-worker-io:8081/\"" "io_client_certificate_chain_file = \"/run/secrets/vfs-io-client-tls/tls.crt\"" "management_url = \"https://filebelt-vfs-management:8088/\"" "[backend_tls.vfs]" "[backend_tls.vfs_management]" -}}
{{- if not (contains $required $renderedFilebeltConfig) -}}
{{- fail (printf "an enabled mount protocol requires configuration.filebelt setting %s" $required) -}}
{{- end -}}
{{- end -}}
{{- if $headscaleRequired -}}
{{- if not (regexMatch "(?m)^\\[mounts\\.headscale\\]\\s*$[\\s\\S]*^enabled = true\\s*$" $renderedFilebeltConfig) -}}
{{- fail "enabled SMB or FTP/FTPS requires Headscale synchronization" -}}
{{- end -}}
{{- end -}}
{{- range $workload := list .Values.mounts.smb .Values.mounts.ftpFtps -}}
{{- if and $workload.enabled (eq $workload.tailstateClaim "") -}}
{{- fail "an enabled SMB or FTP/FTPS gateway requires an operator-provided RWO tailstate claim" -}}
{{- end -}}
{{- end -}}
{{- if .Values.mounts.nfs.enabled -}}
{{- $zeroDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000" -}}
{{- if or (eq (index .Values.images "filebelt-nfs-gateway").digest $zeroDigest) (eq .Values.images.tailscaled.digest $zeroDigest) -}}
{{- fail "mounts.nfs.enabled requires published non-sentinel NFS gateway and tailscaled image digests" -}}
{{- end -}}
{{- if or (eq .Values.mounts.nfs.realm "") (eq .Values.mounts.nfs.idmapDomain "") (eq .Values.mounts.nfs.tailstateClaim "") (eq .Values.mounts.nfs.recoveryClaim "") -}}
{{- fail "mounts.nfs.enabled requires an exact realm, idmap domain, and distinct operator-owned RWO tailstate and recovery claims" -}}
{{- end -}}
{{- if eq .Values.mounts.nfs.tailstateClaim .Values.mounts.nfs.recoveryClaim -}}
{{- fail "NFS tailstate and recovery claims must be distinct" -}}
{{- end -}}
{{- if or (eq (len .Values.mounts.nfs.ganesha.command) 0) (eq (len .Values.mounts.nfs.ganesha.healthCommand) 0) (eq (len .Values.mounts.nfs.ganesha.preStopCommand) 0) (eq .Values.mounts.nfs.ganesha.configMap.name "") (eq (len .Values.mounts.nfs.bridge.command) 0) (eq (len .Values.mounts.nfs.bridge.healthCommand) 0) (eq (len .Values.mounts.nfs.bridge.preStopCommand) 0) (eq .Values.mounts.nfs.bridge.configMap.name "") -}}
{{- fail "mounts.nfs.enabled requires explicit Ganesha and bridge command, health, preStop, and ConfigMap ABI contracts" -}}
{{- end -}}
{{- if eq .Values.mounts.nfs.ganesha.configMap.name .Values.mounts.nfs.bridge.configMap.name -}}
{{- fail "NFS Ganesha and bridge configuration projections must be distinct" -}}
{{- end -}}
{{- if or (eq .Values.secrets.nfsGaneshaKeytab.name .Values.secrets.nfsBridgeVfsClientTls.name) (eq .Values.secrets.nfsGaneshaKeytab.name .Values.secrets.nfsHandleKeyring.name) (eq .Values.secrets.nfsBridgeVfsClientTls.name .Values.secrets.nfsHandleKeyring.name) -}}
{{- fail "NFS Ganesha keytab, bridge VFS identity, and VFS handle-key Secrets must be distinct" -}}
{{- end -}}
{{- if ne (int .Values.networkPolicy.headscale.port) 443 -}}
{{- fail "NFS tailnet control egress is fixed to HTTPS port 443; KDC egress is forbidden" -}}
{{- end -}}
{{- range $required := list "[mounts.nfs]" "enabled = true" "gateway_uri_san = \"spiffe://filebelt/nfs-gateway/vfs\"" (printf "realm = %q" .Values.mounts.nfs.realm) (printf "idmap_domain = %q" .Values.mounts.nfs.idmapDomain) "handle_keyring_file = \"/run/secrets/nfs-handle-keyring.json\"" -}}
{{- if not (contains $required $renderedFilebeltConfig) -}}
{{- fail (printf "mounts.nfs.enabled requires configuration.filebelt setting %s" $required) -}}
{{- end -}}
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
{{- $securityDescendantSharesOperations := list "security-descendant-shares-status" "security-descendant-shares-repair" "security-descendant-shares-verify" "security-descendant-shares-activate" -}}
{{- if has .Values.operation.type $securityDescendantSharesOperations -}}
{{- if or (ne .Values.operation.payloadId "") (ne (len .Values.operation.args) 0) (ne .Values.operation.checkpoint.secretName "") -}}
{{- fail "security descendant-share operations do not accept payloadId, args, or checkpoint input" -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.operation.type "security-descendant-shares-status" -}}
{{- if or (ne .Values.operation.tenantSlugConfirmation "") (ne .Values.operation.actorPrincipalId "") -}}
{{- fail "security-descendant-shares-status accepts only operation.operationId" -}}
{{- end -}}
{{- end -}}
{{- if has .Values.operation.type (list "security-descendant-shares-repair" "security-descendant-shares-verify" "security-descendant-shares-activate") -}}
{{- if or (eq .Values.operation.tenantSlugConfirmation "") (eq .Values.operation.actorPrincipalId "") -}}
{{- fail "security descendant-share repair, verify, and activate require tenant confirmation and actor principal ID" -}}
{{- end -}}
{{- end -}}
{{- if and (has .Values.operation.type (list "keys-audit" "recovery-checkpoint" "recovery-verify")) (not .Values.deployment.quiesced) -}}
{{- fail "keyset audit and recovery operations require deployment.quiesced=true" -}}
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
