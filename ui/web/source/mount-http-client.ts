// SPDX-License-Identifier: Apache-2.0

import createClient from "openapi-fetch";
import type { Client } from "openapi-fetch";

import { AuthenticationRequiredError } from "./client.js";
import type { components, paths } from "./generated/openapi.js";

export type MountOverview = components["schemas"]["MountOverview"];
export type MountProtocol = components["schemas"]["MountPolicy"]["protocol"];
export type PutMountPolicy = components["schemas"]["PutMountPolicy"];
export type CreateMountCredential = components["schemas"]["CreateMountCredential"];
export type CreatedMountCredential = components["schemas"]["CreatedMountCredential"];

interface ApiResult<T> {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly data?: T;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly error?: unknown;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly response: Response;
}

interface MutationHeaders {
  Origin: string;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- HTTP requires this exact Fetch Metadata header name.
  "Sec-Fetch-Site": "same-origin";
  // eslint-disable-next-line @typescript-eslint/naming-convention -- FileBelt HTTP requests require this exact CSRF header name.
  "X-FileBelt-Csrf": string;
}

type SessionResponse = components["schemas"]["Session"];

export class MountReauthenticationRequiredError extends Error {
  constructor() {
    super("Recent OIDC authentication is required.");
    this.name = "MountReauthenticationRequiredError";
  }
}

export interface MountSettingsClient {
  createCredential(Input: CreateMountCredential): Promise<CreatedMountCredential>;
  getOverview(Signal?: AbortSignal): Promise<MountOverview>;
  putPolicy(Protocol: MountProtocol, Input: PutMountPolicy): Promise<void>;
  revokeCredential(CredentialId: string): Promise<void>;
}

export class HttpMountSettingsClient implements MountSettingsClient {
  readonly #Api: Client<paths>;
  readonly #Origin: string;
  #CsrfToken: string | null = null;

  constructor(
    FetchImplementation: typeof fetch = globalThis.fetch.bind(globalThis),
    BaseUrl: string = DefaultBaseUrl(),
  ) {
    this.#Origin = new URL(BaseUrl).origin;
    this.#Api = createClient<paths>({
      baseUrl: BaseUrl,
      credentials: "same-origin",
      fetch: (Request) => FetchImplementation(Request),
    });
  }

  async getOverview(Signal?: AbortSignal): Promise<MountOverview> {
    const Result = await this.#Api.GET(
      "/api/v1/mounts",
      Signal === undefined ? {} : { signal: Signal },
    );
    return RequireData<MountOverview>(Result);
  }

  async putPolicy(Protocol: MountProtocol, Input: PutMountPolicy): Promise<void> {
    await RequireSuccess(
      await this.#Api.PUT("/api/v1/mounts/policies/{protocol}", {
        body: Input,
        params: { header: await this.#mutationHeaders(), path: { protocol: Protocol } },
      }),
    );
  }

  async createCredential(Input: CreateMountCredential): Promise<CreatedMountCredential> {
    return RequireData<CreatedMountCredential>(
      await this.#Api.POST("/api/v1/mounts/credentials", {
        body: Input,
        params: { header: await this.#mutationHeaders() },
      }),
    );
  }

  async revokeCredential(CredentialId: string): Promise<void> {
    await RequireSuccess(
      await this.#Api.DELETE("/api/v1/mounts/credentials/{credential_id}", {
        params: {
          header: await this.#mutationHeaders(),
          path: { credential_id: CredentialId },
        },
      }),
    );
  }

  async #mutationHeaders(): Promise<MutationHeaders> {
    if (this.#CsrfToken === null) {
      const Session = RequireData<SessionResponse>(await this.#Api.GET("/api/v1/session"));
      this.#CsrfToken = Session.csrf_token;
    }
    return {
      Origin: this.#Origin,
      "Sec-Fetch-Site": "same-origin",
      "X-FileBelt-Csrf": this.#CsrfToken,
    };
  }
}

function DefaultBaseUrl(): string {
  return typeof window === "undefined" ? "https://filebelt.localhost" : window.location.origin;
}

function RequireData<T>(Result: ApiResult<unknown>): T {
  if (Result.response.ok && Result.data !== undefined) return Result.data as T;
  throw RequestError(Result);
}

async function RequireSuccess(Result: ApiResult<unknown>): Promise<void> {
  if (!Result.response.ok) throw RequestError(Result);
}

function RequestError(Result: ApiResult<unknown>): Error {
  if (Result.response.status === 401) return new AuthenticationRequiredError();
  const Code = ProblemCode(Result.error);
  if (Code === "mount.reauthentication_required") return new MountReauthenticationRequiredError();
  const Title = ProblemTitle(Result.error);
  return new Error(Title ?? `FileBelt mount request failed (${Result.response.status}).`);
}

function ProblemCode(Value: unknown): string | null {
  if (typeof Value !== "object" || Value === null || !("code" in Value)) return null;
  return typeof Value.code === "string" ? Value.code : null;
}

function ProblemTitle(Value: unknown): string | null {
  if (typeof Value !== "object" || Value === null || !("title" in Value)) return null;
  return typeof Value.title === "string" ? Value.title : null;
}
