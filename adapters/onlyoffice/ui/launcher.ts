// SPDX-License-Identifier: AGPL-3.0-only

export type LauncherState = 'idle' | 'loading-api' | 'launching' | 'ready' | 'error'

export interface LaunchResponse {
  /* oxlint-disable filebelt/pascal-case -- ONLYOFFICE launch responses retain provider field names. */
  apiJsUrl: string
  editorConfig: Record<string, unknown>
  /* oxlint-enable filebelt/pascal-case */
}

export interface LauncherView {
  SetState(State: LauncherState, Message: string): void
  SetLaunchEnabled(Enabled: boolean): void
}

/**
 * A per-tab launcher. It deliberately uses no local/session storage, so a
 * launch must be redeemed by the server for every new tab.
 */
export class OnlyOfficeLauncher {
  #State: LauncherState = 'idle'
  #ProviderApi: Promise<void> | undefined

  public constructor(private readonly View: LauncherView) {
    this.View.SetState('idle', 'Editor is ready to launch.')
    this.View.SetLaunchEnabled(true)
  }

  public get State(): LauncherState {
    return this.#State
  }

  public async Launch(Launch: () => Promise<LaunchResponse>): Promise<void> {
    if (this.#State === 'launching' || this.#State === 'loading-api') return
    this.#State = 'launching'
    this.View.SetLaunchEnabled(false)
    this.View.SetState(this.#State, 'Preparing secure editor launch.')
    try {
      const Response = await Launch()
      this.#State = 'loading-api'
      this.View.SetState(this.#State, 'Loading editor provider.')
      await this.LoadProviderApi(Response.apiJsUrl)
      const DocsApi = window.DocsAPI
      if (DocsApi === undefined) throw new Error('provider API did not expose DocsAPI')
      DocsApi.DocEditor('onlyoffice-editor', Response.editorConfig)
      this.#State = 'ready'
      this.View.SetState(this.#State, 'Editor is ready.')
    } catch {
      this.#State = 'error'
      this.View.SetState(this.#State, 'Unable to launch the editor. Try again.')
      this.View.SetLaunchEnabled(true)
    }
  }

  private async LoadProviderApi(ApiJsUrl: string): Promise<void> {
    if (this.#ProviderApi !== undefined) return this.#ProviderApi
    this.#ProviderApi = new Promise((Resolve, Reject) => {
      const Script = document.createElement('script')
      Script.src = ApiJsUrl
      Script.async = true
      Script.referrerPolicy = 'no-referrer'
      Script.onload = () => {
        Resolve()
      }
      Script.onerror = () => {
        Reject(new Error('provider API failed to load'))
      }
      document.head.append(Script)
    })
    return this.#ProviderApi
  }
}

declare global {
  interface Window {
    DocsAPI?: {
      DocEditor(ElementId: string, Config: Readonly<Record<string, unknown>>): unknown
    }
  }
}
