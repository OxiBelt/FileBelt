// SPDX-License-Identifier: Apache-2.0

import { createHash, generateKeyPairSync, randomBytes, sign, timingSafeEqual } from 'node:crypto'
import { Buffer } from 'node:buffer'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import process from 'node:process'
import { URL, URLSearchParams } from 'node:url'

const issuer = 'http://filebelt-oidc:8083/'
const publicAuthorizationEndpoint = 'https://filebelt.localhost:8443/_filebelt-test-oidc/authorize'
const redirectUri = 'https://filebelt.localhost:8443/api/v1/auth/callback'
const clientId = 'filebelt'
const clientSecret = readFileSync('/run/secrets/oidc-client-secret', 'utf8').trim()
const keyId = 'filebelt-phase2-fixture-1'
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const publicJwk = publicKey.export({ format: 'jwk' })
const codes = new Map()
const users = Object.freeze({
  admin: Object.freeze({
    email: 'admin@example.test',
    name: 'FileBelt Administrator',
    preferred_username: 'admin',
    sub: 'filebelt-development-admin',
  }),
  member: Object.freeze({
    email: 'member@example.test',
    name: 'FileBelt Member',
    preferred_username: 'member',
    sub: 'filebelt-development-member',
  }),
})
const configuration = Object.freeze({
  issuer,
  authorization_endpoint: publicAuthorizationEndpoint,
  token_endpoint: `${issuer}token`,
  jwks_uri: `${issuer}jwks`,
  response_types_supported: ['code'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
  scopes_supported: ['openid', 'email', 'profile'],
  token_endpoint_auth_methods_supported: ['client_secret_post'],
  code_challenge_methods_supported: ['S256'],
})

function base64url(value) {
  return Buffer.from(value).toString('base64url')
}

function json(response, status, body) {
  response.statusCode = status
  response.setHeader('Cache-Control', 'no-store')
  response.setHeader('Content-Type', 'application/json')
  response.setHeader('X-Content-Type-Options', 'nosniff')
  response.end(JSON.stringify(body))
}

function oauthError(response, status, error, description) {
  json(response, status, { error, error_description: description })
}

function equalSecret(left, right) {
  const leftDigest = createHash('sha256').update(left).digest()
  const rightDigest = createHash('sha256').update(right).digest()
  return timingSafeEqual(leftDigest, rightDigest)
}

function jwt(claims) {
  const header = base64url(JSON.stringify({ alg: 'RS256', kid: keyId, typ: 'JWT' }))
  const payload = base64url(JSON.stringify(claims))
  const signingInput = `${header}.${payload}`
  const signature = sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url')
  return `${signingInput}.${signature}`
}

function authorize(url, response) {
  const parameters = url.searchParams
  if (
    parameters.get('response_type') !== 'code' ||
    parameters.get('client_id') !== clientId ||
    parameters.get('redirect_uri') !== redirectUri ||
    parameters.get('code_challenge_method') !== 'S256'
  ) {
    oauthError(response, 400, 'invalid_request', 'The authorization request is invalid.')
    return
  }
  const state = parameters.get('state')
  const nonce = parameters.get('nonce')
  const challenge = parameters.get('code_challenge')
  if (!state || !nonce || !challenge) {
    oauthError(response, 400, 'invalid_request', 'State, nonce, and PKCE are required.')
    return
  }
  const selected = parameters.get('fixture_user')
  const user = selected === null ? undefined : users[selected]
  if (user === undefined) {
    response.statusCode = 200
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'")
    response.setHeader('Content-Type', 'text/html; charset=utf-8')
    response.end(
      `<!doctype html><html lang="en"><meta charset="utf-8"><title>FileBelt test identity</title><style>body{font:16px system-ui;max-width:36rem;margin:4rem auto}a{display:block;margin:1rem;padding:1rem;border:1px solid}</style><h1>Development identities</h1><p>This deterministic issuer is for Docker integration only.</p><a href="${escapeHtml(url.pathname + url.search)}&amp;fixture_user=admin">Administrator</a><a href="${escapeHtml(url.pathname + url.search)}&amp;fixture_user=member">Member</a></html>`,
    )
    return
  }
  const code = randomBytes(32).toString('base64url')
  codes.set(code, {
    challenge,
    expiresAt: Date.now() + 60_000,
    nonce,
    user,
  })
  const callback = new URL(redirectUri)
  callback.searchParams.set('code', code)
  callback.searchParams.set('state', state)
  response.statusCode = 303
  response.setHeader('Cache-Control', 'no-store')
  response.setHeader('Location', callback.toString())
  response.end()
}

async function token(request, response) {
  let body = ''
  for await (const chunk of request) {
    body += chunk
    if (body.length > 16_384) {
      oauthError(response, 413, 'invalid_request', 'The token request is too large.')
      return
    }
  }
  const parameters = new URLSearchParams(body)
  const code = parameters.get('code') ?? ''
  const record = codes.get(code)
  codes.delete(code)
  if (
    record === undefined ||
    record.expiresAt < Date.now() ||
    parameters.get('grant_type') !== 'authorization_code' ||
    parameters.get('redirect_uri') !== redirectUri ||
    parameters.get('client_id') !== clientId ||
    !equalSecret(parameters.get('client_secret') ?? '', clientSecret)
  ) {
    oauthError(response, 400, 'invalid_grant', 'The authorization code is invalid or expired.')
    return
  }
  const verifier = parameters.get('code_verifier') ?? ''
  const actualChallenge = createHash('sha256').update(verifier).digest('base64url')
  if (!equalSecret(actualChallenge, record.challenge)) {
    oauthError(response, 400, 'invalid_grant', 'The PKCE verifier is invalid.')
    return
  }
  const now = Math.floor(Date.now() / 1000)
  const accessToken = randomBytes(32).toString('base64url')
  json(response, 200, {
    access_token: accessToken,
    expires_in: 300,
    id_token: jwt({
      aud: clientId,
      auth_time: now,
      email: record.user.email,
      email_verified: true,
      exp: now + 300,
      iat: now,
      iss: issuer,
      name: record.user.name,
      nonce: record.nonce,
      preferred_username: record.user.preferred_username,
      sub: record.user.sub,
    }),
    token_type: 'Bearer',
  })
}

function escapeHtml(value) {
  return value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;')
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? '/', issuer)
  if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
    json(response, 200, configuration)
    return
  }
  if (request.method === 'GET' && url.pathname === '/jwks') {
    json(response, 200, { keys: [{ ...publicJwk, alg: 'RS256', kid: keyId, use: 'sig' }] })
    return
  }
  if (
    request.method === 'GET' &&
    ['/authorize', '/_filebelt-test-oidc/authorize'].includes(url.pathname)
  ) {
    authorize(url, response)
    return
  }
  if (request.method === 'POST' && url.pathname === '/token') {
    await token(request, response)
    return
  }
  if (request.method === 'GET' && url.pathname === '/health') {
    json(response, 200, { status: 'ready' })
    return
  }
  json(response, 404, { error: 'not_found' })
})

server.listen(8083, '0.0.0.0', () => {
  process.stdout.write('FileBelt deterministic Docker OIDC fixture ready\n')
})

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)))
}
