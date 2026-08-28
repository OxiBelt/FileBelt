// SPDX-License-Identifier: Apache-2.0

import process from 'node:process'

const Configuration = JSON.parse(process.env.FILEBELT_PHASE8_DRIVER_CONFIG ?? 'null')
if (
  Configuration === null ||
  typeof Configuration !== 'object' ||
  !Array.isArray(Configuration.endpoints) ||
  !Number.isInteger(Configuration.durationMilliseconds) ||
  Configuration.durationMilliseconds < 0 ||
  !Number.isInteger(Configuration.iterations) ||
  Configuration.iterations < 1
) {
  throw new Error('internal health qualification configuration is invalid')
}

const Delay = (Milliseconds) =>
  new Promise((Resolve) => {
    setTimeout(Resolve, Milliseconds)
  })

async function Request(Url) {
  const Started = performance.now()
  const Response = await fetch(Url, { signal: AbortSignal.timeout(5_000) })
  await Response.arrayBuffer()
  return { Milliseconds: performance.now() - Started, Status: Response.status }
}

async function Exercise(Endpoint) {
  if (
    typeof Endpoint !== 'object' ||
    typeof Endpoint.role !== 'string' ||
    typeof Endpoint.url !== 'string'
  ) {
    throw new Error('internal health endpoint is invalid')
  }
  const Missing = new URL('/__filebelt_phase8_missing', Endpoint.url).toString()
  const Failure = await Request(Missing)
  if (Failure.Status !== 404) {
    throw new Error(`${Endpoint.role} expected missing-route 404, observed ${Failure.Status}`)
  }
  const Samples = []
  const Deadline = performance.now() + Configuration.durationMilliseconds
  do {
    const Success = await Request(Endpoint.url)
    if (Success.Status !== 204) {
      throw new Error(`${Endpoint.role} expected readiness 204, observed ${Success.Status}`)
    }
    Samples.push(Number(Success.Milliseconds.toFixed(3)))
    if (Configuration.durationMilliseconds > 0) await Delay(25)
  } while (Samples.length < Configuration.iterations || performance.now() < Deadline)
  return {
    role: Endpoint.role,
    endpoint: Endpoint.url,
    samplesMilliseconds: Samples,
    successAssertion: {
      expected: 'GET /health/ready returns 204',
      observed: 'GET /health/ready returned 204',
      passed: true,
    },
    failureAssertion: {
      expected: 'GET unknown operations route returns 404',
      observed: 'GET unknown operations route returned 404',
      passed: true,
    },
    cleanup: {
      status: 'not_required',
      detail: 'read-only health requests created no endpoint state',
    },
  }
}

const Results = await Promise.all(Configuration.endpoints.map(Exercise))
process.stdout.write(`${JSON.stringify(Results)}\n`)
