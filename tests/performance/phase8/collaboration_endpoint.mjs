// SPDX-License-Identifier: Apache-2.0

import process from 'node:process'
import { createHash, randomBytes } from 'node:crypto'
import { connect as connectTls } from 'node:tls'

const Chunks = []
for await (const Chunk of process.stdin) Chunks.push(Chunk)
const Configuration = JSON.parse(Buffer.concat(Chunks).toString('utf8'))
if (
  typeof Configuration?.origin !== 'string' ||
  typeof Configuration?.cookie !== 'string' ||
  typeof Configuration?.csrf !== 'string' ||
  typeof Configuration?.driveId !== 'string' ||
  typeof Configuration?.nodeId !== 'string' ||
  !Number.isInteger(Configuration.durationMilliseconds) ||
  Configuration.durationMilliseconds < 0 ||
  !Number.isInteger(Configuration.iterations) ||
  Configuration.iterations < 1
) {
  throw new Error('collaboration qualification configuration is invalid')
}

function Varint(Value) {
  const Bytes = []
  let Remaining = Value
  do {
    let Byte = Remaining & 0x7f
    Remaining = Math.floor(Remaining / 128)
    if (Remaining > 0) Byte |= 0x80
    Bytes.push(Byte)
  } while (Remaining > 0)
  return Bytes
}

function Field(NumberValue, Bytes) {
  return [...Varint((NumberValue << 3) | 2), ...Varint(Bytes.length), ...Bytes]
}

function Hello(Grant) {
  const Text = (Value) => [...new TextEncoder().encode(Value)]
  const Inner = [
    ...Field(1, Text(Grant.authorization)),
    ...Field(2, Text(Grant.room.room_id)),
    ...Varint(3 << 3),
    ...Varint(1),
    ...Varint(4 << 3),
    ...Varint(1),
  ]
  return new Uint8Array(Field(1, Inner))
}

async function Grant() {
  const Response = await fetch(
    `${Configuration.origin}/api/v1/drives/${Configuration.driveId}/nodes/${Configuration.nodeId}/collaboration-grants`,
    {
      body: JSON.stringify({
        client_id: crypto.randomUUID(),
        presence_mode: 'pseudonym',
        transport: 'websocket',
      }),
      headers: {
        'Content-Type': 'application/json',
        Cookie: Configuration.cookie,
        'Idempotency-Key': crypto.randomUUID(),
        Origin: Configuration.origin,
        'Sec-Fetch-Site': 'same-origin',
        'X-FileBelt-Csrf': Configuration.csrf,
      },
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    },
  )
  if (Response.status !== 201) {
    throw new Error(`collaboration grant expected 201, observed ${Response.status}`)
  }
  const Value = await Response.json()
  const Endpoint = Value.endpoints.find((Item) => Item.transport === 'websocket')?.url
  if (typeof Endpoint !== 'string' || typeof Value.room?.room_id !== 'string') {
    throw new Error('collaboration grant omitted its WebSocket endpoint or room ID')
  }
  return { Endpoint, Value }
}

function ClientBinaryFrame(Payload) {
  const Mask = randomBytes(4)
  let Header
  if (Payload.length <= 125) {
    Header = Buffer.from([0x82, 0x80 | Payload.length])
  } else if (Payload.length <= 0xffff) {
    Header = Buffer.from([0x82, 0xfe, Payload.length >> 8, Payload.length & 0xff])
  } else {
    throw new Error('collaboration Hello exceeds the bounded WebSocket fixture frame')
  }
  const Masked = Buffer.allocUnsafe(Payload.length)
  for (let Index = 0; Index < Payload.length; Index += 1) {
    Masked[Index] = Payload[Index] ^ Mask[Index % Mask.length]
  }
  return Buffer.concat([Header, Mask, Masked])
}

function ServerBinaryPayload(Value) {
  if (Value.length < 2) return undefined
  if ((Value[0] & 0x80) === 0 || (Value[0] & 0x0f) !== 0x02 || (Value[1] & 0x80) !== 0) {
    throw new Error('collaboration server returned an unsupported WebSocket frame')
  }
  let Length = Value[1] & 0x7f
  let Offset = 2
  if (Length === 126) {
    if (Value.length < 4) return undefined
    Length = Value.readUInt16BE(2)
    Offset = 4
  } else if (Length === 127) {
    if (Value.length < 10) return undefined
    const Wide = Value.readBigUInt64BE(2)
    if (Wide > 8n * 1024n * 1024n) {
      throw new Error('collaboration server frame exceeds the fixture bound')
    }
    Length = Number(Wide)
    Offset = 10
  }
  if (Value.length < Offset + Length) return undefined
  return Value.subarray(Offset, Offset + Length)
}

function Invoke(Endpoint, Value) {
  return new Promise((Resolve, Reject) => {
    const Started = performance.now()
    const Target = new URL(Endpoint)
    if (Target.protocol !== 'wss:') {
      Reject(new Error('collaboration endpoint is not wss'))
      return
    }
    const Key = randomBytes(16).toString('base64')
    const ExpectedAccept = createHash('sha1')
      .update(`${Key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64')
    const Socket = connectTls({
      host: Target.hostname,
      port: Number(Target.port || 443),
      servername: Target.hostname,
      ALPNProtocols: ['http/1.1'],
      rejectUnauthorized: true,
    })
    let BufferValue = Buffer.alloc(0)
    let Upgraded = false
    let Settled = false
    const Finish = (Callback, Result) => {
      if (Settled) return
      Settled = true
      clearTimeout(Timer)
      Socket.destroy()
      Callback(Result)
    }
    const Timer = setTimeout(
      () => Finish(Reject, new Error('collaboration WebSocket response timed out')),
      10_000,
    )
    Socket.once('secureConnect', () => {
      const Path = `${Target.pathname}${Target.search}`
      Socket.write(
        [
          `GET ${Path} HTTP/1.1`,
          `Host: ${Target.host}`,
          `Origin: ${Configuration.origin}`,
          'Sec-Fetch-Site: same-origin',
          `Cookie: ${Configuration.cookie}`,
          'Upgrade: websocket',
          'Connection: Upgrade',
          `Sec-WebSocket-Key: ${Key}`,
          'Sec-WebSocket-Version: 13',
          '',
          '',
        ].join('\r\n'),
      )
    })
    Socket.on('data', (Chunk) => {
      try {
        BufferValue = Buffer.concat([BufferValue, Chunk])
        if (!Upgraded) {
          if (BufferValue.length > 16 * 1024) {
            throw new Error('collaboration WebSocket upgrade headers exceed the fixture bound')
          }
          const End = BufferValue.indexOf('\r\n\r\n')
          if (End === -1) return
          const Lines = BufferValue.subarray(0, End).toString('latin1').split('\r\n')
          const Headers = new Map(
            Lines.slice(1).map((Line) => {
              const Separator = Line.indexOf(':')
              return [Line.slice(0, Separator).toLowerCase(), Line.slice(Separator + 1).trim()]
            }),
          )
          if (
            Lines[0] !== 'HTTP/1.1 101 Switching Protocols' ||
            Headers.get('upgrade')?.toLowerCase() !== 'websocket' ||
            !Headers.get('connection')
              ?.toLowerCase()
              .split(/\s*,\s*/)
              .includes('upgrade') ||
            Headers.get('sec-websocket-accept') !== ExpectedAccept
          ) {
            throw new Error(`collaboration WebSocket upgrade failed: ${Lines[0]}`)
          }
          BufferValue = BufferValue.subarray(End + 4)
          Upgraded = true
          Socket.write(ClientBinaryFrame(Buffer.from(Hello(Value))))
        }
        const Payload = ServerBinaryPayload(BufferValue)
        if (Payload === undefined) return
        Finish(Resolve, {
          FirstByte: Payload[0],
          Milliseconds: Number((performance.now() - Started).toFixed(3)),
        })
      } catch (ErrorValue) {
        Finish(Reject, ErrorValue)
      }
    })
    Socket.once('error', (ErrorValue) =>
      Finish(Reject, new Error(`collaboration WebSocket transport failed: ${ErrorValue.message}`)),
    )
    Socket.once('close', () =>
      Finish(Reject, new Error('collaboration WebSocket closed before a response')),
    )
  })
}

const FirstGrant = await Grant()
const Success = await Invoke(FirstGrant.Endpoint, FirstGrant.Value)
if (Success.FirstByte !== 0x1a) {
  throw new Error(
    `first collaboration grant expected sync frame 0x1a, observed 0x${Success.FirstByte.toString(16)}`,
  )
}
const Reused = await Invoke(FirstGrant.Endpoint, FirstGrant.Value)
if (Reused.FirstByte !== 0x4a) {
  throw new Error(
    `reused collaboration grant expected rejection frame 0x4a, observed 0x${Reused.FirstByte.toString(16)}`,
  )
}

const Samples = [Success.Milliseconds]
const Deadline = performance.now() + Configuration.durationMilliseconds
while (Samples.length < Configuration.iterations || performance.now() < Deadline) {
  const CurrentGrant = await Grant()
  const Result = await Invoke(CurrentGrant.Endpoint, CurrentGrant.Value)
  if (Result.FirstByte !== 0x1a) {
    throw new Error(
      `collaboration load expected sync frame 0x1a, observed 0x${Result.FirstByte.toString(16)}`,
    )
  }
  Samples.push(Result.Milliseconds)
}

process.stdout.write(
  `${JSON.stringify({
    endpoint: FirstGrant.Endpoint,
    samplesMilliseconds: Samples,
    successAssertion: {
      expected: 'fresh grant returns collaboration sync frame 0x1a',
      observed: 'fresh grant returned collaboration sync frame 0x1a',
      passed: true,
    },
    failureAssertion: {
      expected: 'reused one-use grant returns rejection frame 0x4a',
      observed: 'reused one-use grant returned rejection frame 0x4a',
      passed: true,
    },
  })}\n`,
)
