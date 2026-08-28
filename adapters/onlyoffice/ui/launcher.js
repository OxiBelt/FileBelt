// SPDX-License-Identifier: AGPL-3.0-only

// Browser-ready equivalent of launcher.ts. It is intentionally committed as a
// small standalone module because this isolated adapter has no bundler or
// Apache web-package dependency.
const descriptorElement = document.getElementById('onlyoffice-launch-descriptor')
const stateElement = document.getElementById('onlyoffice-launch-state')
const launchButton = document.getElementById('onlyoffice-launch-button')

if (
  !(descriptorElement instanceof HTMLScriptElement) ||
  !(stateElement instanceof HTMLElement) ||
  !(launchButton instanceof HTMLButtonElement)
) {
  throw new Error('ONLYOFFICE launcher shell is incomplete')
}

const descriptor = JSON.parse(descriptorElement.textContent ?? '')
const setState = (state, message) => {
  stateElement.dataset.state = state
  stateElement.textContent = message
}
let providerApi
let state = 'idle'

const loadProviderApi = (apiJsUrl) => {
  if (providerApi !== undefined) return providerApi
  providerApi = new Promise((resolve, reject) => {
    const script = document.createElement('script')
    script.src = apiJsUrl
    script.async = true
    script.referrerPolicy = 'no-referrer'
    script.onload = resolve
    script.onerror = () => reject(new Error('provider API failed to load'))
    document.head.append(script)
  })
  return providerApi
}

const launch = async () => {
  if (state === 'launching' || state === 'loading-api') return
  state = 'launching'
  launchButton.disabled = true
  setState(state, 'Preparing secure editor launch.')
  try {
    state = 'loading-api'
    setState(state, 'Loading editor provider.')
    await loadProviderApi(descriptor.apiJsUrl)
    if (window.DocsAPI === undefined) throw new Error('provider API did not expose DocsAPI')
    window.DocsAPI.DocEditor('onlyoffice-editor', descriptor.editorConfig)
    state = 'ready'
    setState(state, 'Editor is ready.')
  } catch {
    state = 'error'
    setState(state, 'Unable to launch the editor. Try again.')
    launchButton.disabled = false
  }
}

setState(state, 'Editor is ready to launch.')
launchButton.addEventListener('click', () => {
  void launch()
})
