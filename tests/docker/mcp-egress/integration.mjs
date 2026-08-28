// SPDX-License-Identifier: Apache-2.0

import { Buffer } from 'node:buffer'

export const IntegrationSession = 'filebelt-integration-session'
export const ConfusedIntegrationSession = 'filebelt-confused-integration-session'
export const RedirectFollowPath = '/__filebelt_mcp_redirect_followed'
export const RedirectLocation = `https://filebelt-mcp-egress:8443${RedirectFollowPath}`
export const IntegrationPaths = new Set([
  '/mcp',
  '/credential',
  '/malformed',
  '/oversized',
  '/redirect',
  '/session-confusion',
  '/slow',
])

export function IsIntegrationTarget(Target, Port, TrustProfile, IntegrationHost) {
  return (
    IntegrationHost.length > 0 &&
    TrustProfile === 'integration' &&
    Target.hostname === IntegrationHost &&
    Port === 443 &&
    IntegrationPaths.has(Target.pathname) &&
    Target.search === ''
  )
}

export function IntegrationSessionDenial(Pathname, Method, Session) {
  if (Method === 'initialize') return undefined
  if (Pathname === '/session-confusion' && Session === ConfusedIntegrationSession) {
    return 'fixture detected the injected session identity\n'
  }
  return Session === IntegrationSession ? undefined : 'fixture session mismatch\n'
}

export function IntegrationResponse(
  RequestValue,
  Pathname,
  MaximumResponseBytes,
  GatewayPath = '/',
) {
  if (Pathname === '/redirect' && GatewayPath !== RedirectFollowPath) {
    return { Redirect: RedirectLocation }
  }
  const Method = RequestValue?.method
  const Id = RequestValue?.id
  if (Method === 'notifications/initialized') {
    return {
      Notification: true,
      ...(Pathname === '/session-confusion' ? { Session: ConfusedIntegrationSession } : {}),
    }
  }
  if (Method === 'initialize') {
    if (Pathname === '/malformed') return { Raw: Buffer.from('{not-json') }
    if (Pathname === '/oversized') return { Raw: Buffer.alloc(MaximumResponseBytes + 1, 0x61) }
    return {
      Body: {
        jsonrpc: '2.0',
        id: Id,
        result: {
          protocolVersion: '2026-07-28',
          capabilities: { tools: {} },
          serverInfo: { name: 'FileBelt bounded integration fixture', version: '1' },
        },
      },
      ...(Pathname === '/slow' ? { DelayMs: 6_000 } : {}),
      Session: IntegrationSession,
    }
  }
  if (Method === 'tools/list')
    return {
      Body: {
        jsonrpc: '2.0',
        id: Id,
        result: {
          tools: [
            {
              name: 'echo',
              title: 'Bounded echo',
              description: 'Returns bounded synthetic text',
              inputSchema: { type: 'object' },
              annotations: { readOnlyHint: true },
            },
          ],
        },
      },
    }
  if (Method === 'resources/list')
    return { Body: { jsonrpc: '2.0', id: Id, result: { resources: [] } } }
  if (Method === 'prompts/list')
    return { Body: { jsonrpc: '2.0', id: Id, result: { prompts: [] } } }
  if (Method === 'tools/call')
    return {
      Body: {
        jsonrpc: '2.0',
        id: Id,
        result: { content: [{ type: 'text', text: 'bounded integration result' }] },
      },
    }
  return { Body: { jsonrpc: '2.0', id: Id, error: { code: -32601, message: 'method not found' } } }
}
