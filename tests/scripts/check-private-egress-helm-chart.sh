#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
readonly HELM_BIN="${FILEBELT_HELM_BIN:-helm}"
[[ "$("${HELM_BIN}" version --template '{{ .Version }}')" == "v4.2.4" ]]
root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
chart="${root}/deploy/helm/filebelt-private-egress"
fixture="${chart}/examples/qualification-values.yaml"
if "${HELM_BIN}" template private "${chart}" --namespace filebelt-private-egress | grep -q '^kind:'; then exit 1; fi
if "${HELM_BIN}" template private "${chart}" --namespace wrong >/dev/null 2>&1; then exit 1; fi
rendered="$(mktemp)"
trap 'rm -f -- "${rendered}"' EXIT
"${HELM_BIN}" template private "${chart}" --namespace filebelt-private-egress -f "${fixture}" >"${rendered}"
"${HELM_BIN}" lint "${chart}" --namespace filebelt-private-egress --strict
if "${HELM_BIN}" template private "${chart}" --namespace filebelt-private-egress -f "${fixture}" \
  --set-string 'instances[0].gateway.relayIdentity.name=mcp-private-client' >/dev/null 2>&1; then exit 1; fi
if "${HELM_BIN}" template private "${chart}" --namespace filebelt-private-egress -f "${fixture}" \
  --set-string 'instances[0].name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' >/dev/null 2>&1; then exit 1; fi
if "${HELM_BIN}" template private "${chart}" --namespace filebelt-private-egress -f "${fixture}" \
  --set-json 'instances[0].transports[0].tailscale.dns.to=[{}]' >/dev/null 2>&1; then exit 1; fi
if "${HELM_BIN}" template private "${chart}" --namespace filebelt-private-egress -f "${fixture}" \
  --set-json 'instances[0].transports[0].tailscale.dns.to=[{"namespaceSelector":{"matchLabels":{}}}]' >/dev/null 2>&1; then exit 1; fi
if "${HELM_BIN}" template private "${chart}" --namespace filebelt-private-egress -f "${fixture}" \
  --set-json 'instances[0].transports[0].tailscale.dns.to=[{"ipBlock":{"cidr":"192.0.2.1/32"},"podSelector":{"matchLabels":{"k8s-app":"kube-dns"}}}]' >/dev/null 2>&1; then exit 1; fi
grep -q 'socks5_proxy = "127.0.0.1:1055"' "${rendered}"
grep -q 'name: wireguard-init' "${rendered}"
grep -q 'add: \["NET_ADMIN"\]' "${rendered}"
grep -q 'name: TS_USERSPACE, value: "true"' "${rendered}"
grep -q 'target_addresses = \["100.64.20.10:443"\]' "${rendered}"
grep -q 'target_addresses = \["10.40.0.10:443"\]' "${rendered}"
grep -q 'fsGroup: 10001' "${rendered}"
if grep -Eq '^kind: (Namespace|Secret|PersistentVolumeClaim)$' "${rendered}"; then exit 1; fi
if grep -q 'privileged: true' "${rendered}"; then exit 1; fi
[[ "$(grep -c 'add: \["NET_ADMIN"\]' "${rendered}")" == "1" ]]
