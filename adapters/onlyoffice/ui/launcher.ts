// SPDX-License-Identifier: AGPL-3.0-only

export type LauncherState = "idle" | "loading-api" | "launching" | "ready" | "error";

export interface LaunchResponse {
  apiJsUrl: string;
  editorConfig: Record<string, unknown>;
}

export interface LauncherView {
  setState(State: LauncherState, Message: string): void;
  setLaunchEnabled(Enabled: boolean): void;
}

/**
 * A per-tab launcher. It deliberately uses no local/session storage, so a
 * launch must be redeemed by the server for every new tab.
 */
export class OnlyOfficeLauncher {
  #State: LauncherState = "idle";
  #ProviderApi: Promise<void> | undefined;

  public constructor(private readonly View: LauncherView) {
    this.View.setState("idle", "Editor is ready to launch.");
    this.View.setLaunchEnabled(true);
  }

  public get State(): LauncherState { return this.#State; }

  public async launch(Launch: () => Promise<LaunchResponse>): Promise<void> {
    if (this.#State === "launching" || this.#State === "loading-api") return;
    this.#State = "launching";
    this.View.setLaunchEnabled(false);
    this.View.setState(this.#State, "Preparing secure editor launch.");
    try {
      const Response = await Launch();
      this.#State = "loading-api";
      this.View.setState(this.#State, "Loading editor provider.");
      await this.loadProviderApi(Response.apiJsUrl);
      const DocsApi = window.DocsAPI;
      if (DocsApi === undefined) throw new Error("provider API did not expose DocsAPI");
      DocsApi.DocEditor("onlyoffice-editor", Response.editorConfig);
      this.#State = "ready";
      this.View.setState(this.#State, "Editor is ready.");
    } catch {
      this.#State = "error";
      this.View.setState(this.#State, "Unable to launch the editor. Try again.");
      this.View.setLaunchEnabled(true);
    }
  }

  private loadProviderApi(ApiJsUrl: string): Promise<void> {
    if (this.#ProviderApi !== undefined) return this.#ProviderApi;
    this.#ProviderApi = new Promise((Resolve, Reject) => {
      const Script = document.createElement("script");
      Script.src = ApiJsUrl;
      Script.async = true;
      Script.referrerPolicy = "no-referrer";
      Script.onload = () => Resolve();
      Script.onerror = () => Reject(new Error("provider API failed to load"));
      document.head.append(Script);
    });
    return this.#ProviderApi;
  }
}

declare global {
  interface Window {
    DocsAPI?: {
      DocEditor(ElementId: string, Config: Record<string, unknown>): unknown;
    };
  }
}
