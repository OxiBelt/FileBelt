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
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly data?: T;
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly error?: unknown;
  // oxlint-disable-next-line filebelt/pascal-case -- `openapi-fetch` returns this exact result key.
  readonly response: Response;
}

interface MutationHeaders {
  Origin: string;
  "Sec-Fetch-Site": "same-origin";
  "X-FileBelt-Csrf": string;
}

type SessionResponse = components["schemas"]["Session"];

export class MountReauthenticationRequiredError extends Error {
  constructor() {
    super("Recent OIDC authentication is required.");
    this.name = "MountReauthenticationRequiredError";
  }
}

export class MountCredentialOutcomeUnknownError extends Error {
  readonly CredentialId: string;

  constructor(CredentialId: string) {
    super(
      "The credential creation result is unknown. FileBelt must revoke the operation identifier before another credential is created.",
    );
    this.name = "MountCredentialOutcomeUnknownError";
    this.CredentialId = CredentialId;
  }
}

export interface MountSettingsClient {
  createCredential(Input: CreateMountCredential): Promise<CreatedMountCredential>;
  getOverview(Signal?: Readonly<AbortSignal>): Promise<MountOverview>;
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
      fetch: async (Request) => FetchImplementation(Request),
    });
  }

  async getOverview(Signal?: Readonly<AbortSignal>): Promise<MountOverview> {
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
    const Headers = await this.#mutationHeaders();
    const Result = await (async () => {
      try {
        return await this.#Api.POST("/api/v1/mounts/credentials", {
          body: Input,
          params: { header: Headers },
        });
      } catch {
        throw new MountCredentialOutcomeUnknownError(Input.operation_id);
      }
    })();
    if (Result.response.status >= 500)
      throw new MountCredentialOutcomeUnknownError(Input.operation_id);
    if (Result.response.ok && Result.data === undefined)
      throw new MountCredentialOutcomeUnknownError(Input.operation_id);
    return RequireData<CreatedMountCredential>(Result);
  }

  async revokeCredential(CredentialId: string): Promise<void> {
    const Result = await this.#Api.DELETE("/api/v1/mounts/credentials/{credential_id}", {
      params: {
        header: await this.#mutationHeaders(),
        path: { credential_id: CredentialId },
      },
    });
    // Revocation is the recovery barrier for a caller-owned operation UUID.
    // A definite 404 proves there is no active credential visible to that
    // principal and is therefore already the desired terminal state.
    if (Result.response.status === 404) return;
    await RequireSuccess(Result);
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

// oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- The generated operation at each call site supplies the expected response schema.
function RequireData<T>(Result: ApiResult<unknown>): T {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- openapi-fetch has already selected the generated schema for the successful operation.
  if (Result.response.ok && Result.data !== undefined) return Result.data as T;
  throw RequestError(Result);
}

// oxlint-disable-next-line typescript/require-await -- This helper preserves the Promise contract used by mutation call sites while performing no I/O itself.
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
