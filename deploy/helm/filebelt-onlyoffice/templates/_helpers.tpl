{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "filebelt-onlyoffice.name" -}}
{{- print "filebelt-onlyoffice" -}}
{{- end -}}

{{- define "filebelt-onlyoffice.labels" -}}
app.kubernetes.io/name: filebelt-onlyoffice
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: onlyoffice-adapter
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
filebelt.dev/adapter-license: {{ .Values.image.license | quote }}
filebelt.dev/adapter-source: {{ .Values.image.correspondingSource | quote }}
{{- end -}}

{{- define "filebelt-onlyoffice.image" -}}
{{- $registry := coalesce .Values.image.registryMirror .Values.global.registryMirror .Values.global.registry -}}
{{- printf "%s/%s@%s" $registry .Values.image.repository .Values.image.digest -}}
{{- end -}}

{{- define "filebelt-onlyoffice.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.global.runAsUser }}
runAsGroup: {{ .Values.global.runAsGroup }}
fsGroup: {{ .Values.global.runAsGroup }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile: {type: RuntimeDefault}
supplementalGroups: [{{ .Values.global.runAsGroup }}]
{{- end -}}

{{- define "filebelt-onlyoffice.containerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities: {drop: ["ALL"]}
privileged: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: {{ .Values.global.runAsUser }}
runAsGroup: {{ .Values.global.runAsGroup }}
{{- end -}}

{{- define "filebelt-onlyoffice.validate" -}}
{{- if ne .Release.Namespace .Values.integrationNamespace -}}
{{- fail "install this chart into integrationNamespace; it never creates a namespace" -}}
{{- end -}}
{{- if eq .Values.integrationNamespace .Values.coreNamespace -}}
{{- fail "integrationNamespace must be distinct from coreNamespace" -}}
{{- end -}}
{{- if or (eq (len .Values.networkPolicy.oxibeltIngress.from) 0) (eq (len .Values.networkPolicy.dns.to) 0) (eq (len .Values.networkPolicy.core.to) 0) (eq (len .Values.networkPolicy.io.to) 0) (eq (len .Values.networkPolicy.egressGateway.to) 0) -}}
{{- fail "ONLYOFFICE adapter NetworkPolicy peers must be explicit and nonempty" -}}
{{- end -}}
{{- if and .Values.networkPolicy.otlp.enabled (eq (len .Values.networkPolicy.otlp.to) 0) -}}
{{- fail "enabled OTLP requires an explicit peer allowlist" -}}
{{- end -}}
{{- if regexMatch "\\\"cidr\\\":\\\"[^\\\"]+/0\\\"" (toJson .Values.networkPolicy) -}}
{{- fail "NetworkPolicy must not permit an unrestricted Internet CIDR" -}}
{{- end -}}
{{- end -}}
