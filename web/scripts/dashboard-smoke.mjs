#!/usr/bin/env node
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const host = '127.0.0.1'
const port = process.env.NOTHINGDNS_DASHBOARD_SMOKE_PORT || '4173'
const origin = `http://${host}:${port}`
const routes = ['/', '/dashboard', '/zones', '/upstreams', '/settings', '/about']
const webDir = fileURLToPath(new URL('..', import.meta.url))

const preview = spawn(
  process.platform === 'win32' ? 'npm.cmd' : 'npm',
  ['run', 'preview', '--', '--host', host, '--port', port, '--strictPort'],
  { cwd: webDir, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] },
)

let output = ''
preview.stdout.on('data', (chunk) => {
  output += chunk.toString()
})
preview.stderr.on('data', (chunk) => {
  output += chunk.toString()
})

function killPreview(signal) {
  if (process.platform !== 'win32' && preview.pid) {
    try {
      process.kill(-preview.pid, signal)
      return
    } catch (err) {
      output += `\nfailed to send ${signal} to preview process group: ${err.message}`
    }
  }
  preview.kill(signal)
}

function terminatePreview() {
  if (preview.exitCode !== null || preview.signalCode !== null) {
    return
  }
  killPreview('SIGTERM')
}

async function stopPreview() {
  if (preview.exitCode !== null || preview.signalCode !== null) {
    return
  }
  terminatePreview()
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (preview.exitCode === null && preview.signalCode === null) {
        killPreview('SIGKILL')
      }
      resolve()
    }, 2_000)
    preview.once('exit', () => {
      clearTimeout(timer)
      resolve()
    })
  })
}

process.on('exit', terminatePreview)
process.on('SIGINT', () => {
  terminatePreview()
  process.exit(130)
})
process.on('SIGTERM', () => {
  terminatePreview()
  process.exit(143)
})

async function waitForPreview() {
  const deadline = Date.now() + 15_000
  let lastError
  while (Date.now() < deadline) {
    try {
      const res = await fetch(origin, { signal: AbortSignal.timeout(1_000) })
      if (res.ok) {
        return
      }
      lastError = new Error(`HTTP ${res.status}`)
    } catch (err) {
      lastError = err
    }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  throw new Error(`dashboard preview did not become ready: ${lastError?.message || 'timeout'}\n${output}`)
}

async function assertRoute(route) {
  const res = await fetch(`${origin}${route}`, { signal: AbortSignal.timeout(2_000) })
  if (!res.ok) {
    throw new Error(`${route}: expected 2xx, got ${res.status}`)
  }
  const html = await res.text()
  if (!html.includes('<div id="root"></div>')) {
    throw new Error(`${route}: response is not the dashboard shell`)
  }
  if (!html.includes('/assets/index-')) {
    throw new Error(`${route}: dashboard asset entrypoint is missing`)
  }
}

async function assertEntrypointAsset() {
  const res = await fetch(origin, { signal: AbortSignal.timeout(2_000) })
  const html = await res.text()
  const match = html.match(/src="(\/assets\/index-[^"]+\.js)"/)
  if (!match) {
    throw new Error('dashboard entrypoint script was not found')
  }
  const asset = await fetch(`${origin}${match[1]}`, { signal: AbortSignal.timeout(2_000) })
  if (!asset.ok) {
    throw new Error(`dashboard entrypoint asset returned ${asset.status}`)
  }
  const js = await asset.text()
  if (js.length < 10_000) {
    throw new Error('dashboard entrypoint asset is unexpectedly small')
  }
}

try {
  await waitForPreview()
  for (const route of routes) {
    await assertRoute(route)
  }
  await assertEntrypointAsset()
  console.log(`dashboard smoke passed for ${routes.length} routes at ${origin}`)
} finally {
  await stopPreview()
}
