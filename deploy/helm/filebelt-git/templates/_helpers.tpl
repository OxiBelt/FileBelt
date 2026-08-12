{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "filebelt-git.name" -}}filebelt-git{{- end -}}
{{- define "filebelt-git.labels" -}}
app.kubernetes.io/name: filebelt-git
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: git-adapter
app.kubernetes.io/managed-by: {{ .Release.Service }}
filebelt.dev/adapter-license: {{ .Values.image.license | quote }}
filebelt.dev/adapter-source: {{ .Values.image.correspondingSource | quote }}
{{- end -}}
{{- define "filebelt-git.image" -}}
{{- $registry := coalesce .Values.image.registryMirror .Values.global.registryMirror .Values.global.registry -}}
{{- printf "%s/%s@%s" $registry .Values.image.repository .Values.image.digest -}}
{{- end -}}
{{- define "filebelt-git.validate" -}}
{{- if ne .Release.Namespace .Values.gitNamespace -}}{{- fail "install this chart into gitNamespace; it never creates a namespace" -}}{{- end -}}
{{- if eq .Values.gitNamespace .Values.coreNamespace -}}{{- fail "gitNamespace must be distinct from coreNamespace" -}}{{- end -}}
{{- if eq (len .Values.networkPolicy.coordinatorIngress.from) 0 -}}{{- fail "coordinator ingress peers must be explicit" -}}{{- end -}}
{{- end -}}
