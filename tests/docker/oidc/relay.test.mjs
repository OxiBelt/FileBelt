// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict'
import { Buffer } from 'node:buffer'
import { createConnection, createServer } from 'node:net'
import { test } from 'node:test'

import { createRelay } from './relay.mjs'

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject)
      resolve(server.address())
    })
  })
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
  })
}

test('relay forwards bytes without interpreting the TLS stream', async () => {
  const upstream = createServer((connection) => connection.pipe(connection))
  const upstreamAddress = await listen(upstream)
  const relay = createRelay({
    targetHost: '127.0.0.1',
    targetPort: upstreamAddress.port,
  })
  const relayAddress = await listen(relay)
  const payload = Buffer.from('opaque-tls-record')
  const received = await new Promise((resolve, reject) => {
    const client = createConnection(relayAddress)
    client.once('error', reject)
    client.once('connect', () => client.write(payload))
    client.once('data', (data) => {
      client.end()
      resolve(data)
    })
  })
  assert.deepEqual(received, payload)
  await new Promise((resolve) => relay.shutdown(resolve))
  await close(upstream)
})

test('relay rejects connections above its explicit bound', async () => {
  const upstream = createServer()
  const upstreamAddress = await listen(upstream)
  const relay = createRelay({
    targetHost: '127.0.0.1',
    targetPort: upstreamAddress.port,
    maximumConnections: 1,
  })
  const relayAddress = await listen(relay)
  const first = createConnection(relayAddress)
  await new Promise((resolve, reject) => {
    first.once('connect', resolve)
    first.once('error', reject)
  })
  const second = createConnection(relayAddress)
  await new Promise((resolve, reject) => {
    second.once('close', resolve)
    second.once('error', (error) => {
      if (error.code === 'ECONNRESET') {
        resolve()
      } else {
        reject(error)
      }
    })
  })
  first.destroy()
  await new Promise((resolve) => relay.shutdown(resolve))
  await close(upstream)
})
