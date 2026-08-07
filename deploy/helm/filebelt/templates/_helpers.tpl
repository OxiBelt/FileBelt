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
{{- printf "%s-config-%s" (include "filebelt.name" . | trunc 42 | trimSuffix "-") (.Values.configuration.filebelt | sha256sum | trunc 12) -}}
{{- end -}}

{{- define "filebelt.oxibeltConfigName" -}}
{{- printf "%s-edge-%s" (include "filebelt.name" . | trunc 44 | trimSuffix "-") (.Values.configuration.oxibelt | sha256sum | trunc 12) -}}
{{- end -}}

{{- define "filebelt.secretGenerationDigest" -}}
{{- $generations := dict -}}
{{- range $name, $secret := .Values.secrets -}}
{{- $_ := set $generations $name $secret.generation -}}
{{- end -}}
{{- toJson $generations | sha256sum -}}
{{- end -}}

{{- define "filebelt.validate" -}}
{{- if not (hasPrefix "version = 2" (trim .Values.configuration.filebelt)) -}}
{{- fail "configuration.filebelt must begin with version = 2" -}}
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
