{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "privateEgress.image" -}}{{ printf "%s@%s" .repository .digest }}{{- end -}}
{{- define "privateEgress.name" -}}{{ printf "filebelt-private-egress-%s" . | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "privateEgress.relayName" -}}{{ printf "filebelt-tunnel-relay-%s" . | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "privateEgress.slotName" -}}{{ printf "filebelt-tunnel-%s-%s" .instance .slot | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "privateEgress.security" -}}
allowPrivilegeEscalation: false
capabilities: {drop: ["ALL"]}
privileged: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
{{- end -}}
{{- define "privateEgress.tlsVolume" -}}
secret:
  secretName: {{ .name }}
  defaultMode: 0440
  items:
    - {key: {{ .certificateKey }}, path: tls.crt}
    - {key: {{ .privateKeyKey }}, path: tls.key}
    - {key: {{ .caKey }}, path: ca.crt}
{{- end -}}
{{- define "privateEgress.socket" -}}
{{- if contains ":" .address -}}{{ printf "[%s]:%v" .address .port }}{{- else -}}{{ printf "%s:%v" .address .port }}{{- end -}}
{{- end -}}
{{- define "privateEgress.validate" -}}
{{- if ne .Release.Namespace .Values.namespace }}{{ fail "private-egress.namespace: install into the configured pre-created namespace" }}{{ end -}}
{{- $names := dict -}}
{{- $resourceNames := dict -}}
{{- $identityNames := dict -}}
{{- $tailscaleClaims := dict -}}
{{- $tailscaleAuth := dict -}}
{{- $tailscaleHostnames := dict -}}
{{- $wireguardKeys := dict -}}
{{- $wireguardPresharedKeys := dict -}}
{{- range $instance := .Values.instances -}}
  {{- if hasKey $names $instance.name }}{{ fail "private-egress.instances: instance names must be unique" }}{{ end -}}
  {{- $_ := set $names $instance.name true -}}
  {{- if $instance.enabled -}}
    {{- $gatewayName := printf "filebelt-private-egress-%s" $instance.name -}}
    {{- $relayName := printf "filebelt-tunnel-relay-%s" $instance.name -}}
    {{- range $name := list $gatewayName (printf "%s-config" $gatewayName) (printf "%s-default-deny" $gatewayName) (printf "%s-gateway" $gatewayName) $relayName (printf "%s-config" $relayName) (printf "%s-ingress" $relayName) -}}
      {{- if gt (len $name) 63 }}{{ fail "private-egress.names: a generated Kubernetes name exceeds 63 characters" }}{{ end -}}
      {{- if hasKey $resourceNames $name }}{{ fail "private-egress.names: generated Kubernetes names must be unique" }}{{ end -}}
      {{- $_ := set $resourceNames $name true -}}
    {{- end -}}
    {{- if and (eq $instance.provider "tailscale") (eq $.Values.architecture "riscv64") }}{{ fail "private-egress.architecture: Tailscale supports amd64 and arm64 only" }}{{ end -}}
    {{- range $identity := list $instance.client.identity.name $instance.gateway.serverIdentity.name $instance.gateway.relayIdentity.name $instance.relay.serverIdentity.name -}}
      {{- if hasKey $identityNames $identity }}{{ fail "private-egress.identity: every mTLS hop and instance must use a distinct Secret" }}{{ end -}}
      {{- $_ := set $identityNames $identity true -}}
    {{- end -}}
    {{- if ne (len $instance.target.dialAddresses) (len (uniq $instance.target.dialAddresses)) }}{{ fail "private-egress.target: dial addresses must be unique" }}{{ end -}}
    {{- $slots := dict -}}
    {{- range $slot := $instance.transports -}}
      {{- if hasKey $slots $slot.name }}{{ fail "private-egress.transports: slot names must be unique" }}{{ end -}}
      {{- $_ := set $slots $slot.name true -}}
      {{- $slotName := printf "filebelt-tunnel-%s-%s" $instance.name $slot.name -}}
      {{- range $name := list $slotName (printf "%s-egress" $slotName) -}}
        {{- if gt (len $name) 63 }}{{ fail "private-egress.names: a generated Kubernetes name exceeds 63 characters" }}{{ end -}}
        {{- if hasKey $resourceNames $name }}{{ fail "private-egress.names: generated Kubernetes names must be unique" }}{{ end -}}
        {{- $_ := set $resourceNames $name true -}}
      {{- end -}}
      {{- if eq $instance.provider "tailscale" -}}
        {{- if hasKey $tailscaleClaims $slot.tailscale.stateClaim }}{{ fail "private-egress.tailscale: each slot and instance needs a distinct state claim" }}{{ end -}}
        {{- if hasKey $tailscaleAuth $slot.tailscale.authSecret.name }}{{ fail "private-egress.tailscale: each slot and instance needs a distinct auth Secret" }}{{ end -}}
        {{- if hasKey $tailscaleHostnames $slot.tailscale.hostname }}{{ fail "private-egress.tailscale: each slot and instance needs a distinct hostname" }}{{ end -}}
        {{- $_ := set $tailscaleClaims $slot.tailscale.stateClaim true -}}{{- $_ := set $tailscaleAuth $slot.tailscale.authSecret.name true -}}{{- $_ := set $tailscaleHostnames $slot.tailscale.hostname true -}}
      {{- else -}}
        {{- if hasKey $wireguardKeys $slot.wireguard.privateKeySecret.name }}{{ fail "private-egress.wireguard: each slot and instance needs a distinct private-key Secret" }}{{ end -}}
        {{- $_ := set $wireguardKeys $slot.wireguard.privateKeySecret.name true -}}
        {{- if $slot.wireguard.presharedKeySecret -}}
          {{- if hasKey $wireguardPresharedKeys $slot.wireguard.presharedKeySecret.name }}{{ fail "private-egress.wireguard: each slot and instance needs a distinct preshared-key Secret" }}{{ end -}}
          {{- $_ := set $wireguardPresharedKeys $slot.wireguard.presharedKeySecret.name true -}}
        {{- end -}}
        {{- if ne (len $slot.wireguard.targetCidrs) (len $instance.target.dialAddresses) }}{{ fail "private-egress.wireguard: target CIDRs must map one-to-one to dial addresses" }}{{ end -}}
        {{- $peerCidr := printf "%s/%v" $slot.wireguard.endpointAddress (ternary 128 32 (contains ":" $slot.wireguard.endpointAddress)) -}}
        {{- if ne $peerCidr $slot.wireguard.peerCidr }}{{ fail "private-egress.wireguard: peer CIDR must be the exact endpoint host" }}{{ end -}}
        {{- range $address := $instance.target.dialAddresses -}}
          {{- $targetCidr := printf "%s/%v" $address (ternary 128 32 (contains ":" $address)) -}}
          {{- if not (has $targetCidr $slot.wireguard.targetCidrs) }}{{ fail "private-egress.wireguard: target CIDRs must exactly match dial addresses" }}{{ end -}}
        {{- end -}}
      {{- end -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- end -}}
