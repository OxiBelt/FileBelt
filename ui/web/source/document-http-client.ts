// SPDX-License-Identifier: Apache-2.0

import createClient from "openapi-fetch";
import type { Client } from "openapi-fetch";

import { AuthenticationRequiredError } from "./client.js";
import type { components, paths } from "./generated/openapi.js";

export type DocumentSessionDetail = components["schemas"]["DocumentSessionDetail"];
export type DocumentSessionConflictCopy = components["schemas"]["DocumentSessionConflictCopy"];
export type DocumentSessionLaunchHandoff = components["schemas"]["DocumentSessionLaunchHandoff"];
export type DocumentSessionPage = components["schemas"]["DocumentSessionPage"];
export type DocumentSessionMode = components["schemas"]["CreateDocumentSession"]["mode"];

export interface CreateDocumentSessionInput {
  BaseVersionId: string;
  DriveId: string;
  Mode: DocumentSessionMode;
  NodeId: string;
}

export interface ListDocumentSessionsOptions {
  Cursor?: string;
  Signal?: AbortSignal;
}

/** Provider-neutral browser boundary for document-session controls. */
export interface DocumentSessionClient {
  createSession(Input: CreateDocumentSessionInput): Promise<DocumentSessionDetail>;
  createConflictCopy(SessionId: string, TargetName: string): Promise<DocumentSessionConflictCopy>;
  forceClose(Session: components["schemas"]["DocumentSessionSummary"]): Promise<void>;
  getOwnSession(SessionId: string): Promise<DocumentSessionDetail>;
  listNodeSessions(DriveId: string, NodeId: string, Options?: ListDocumentSessionsOptions): Promise<DocumentSessionPage>;
  listOwnSessions(Options?: ListDocumentSessionsOptions): Promise<DocumentSessionPage>;
  redeemLaunch(SessionId: string): Promise<DocumentSessionLaunchHandoff>;
  revokeOwnSession(SessionId: string): Promise<void>;
}

interface SessionResponse {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Generated OpenAPI response uses this exact key.
  readonly csrf_token: string;
}

interface CsrfHeaders {
  Origin: string;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- HTTP requires this exact Fetch Metadata header name.
  "Sec-Fetch-Site": "same-origin";
  // eslint-disable-next-line @typescript-eslint/naming-convention -- FileBelt HTTP requests require this exact CSRF header name.
  "X-FileBelt-Csrf": string;
}

interface MutationHeaders extends CsrfHeaders {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- FileBelt HTTP requires this exact idempotency header name.
  "Idempotency-Key": string;
}

interface ApiResult<T> {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly data?: T;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly error?: unknown;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly response: Response;
}

const PageLimit = 200;

/** Same-origin adapter for generated document-session operations. */
export class HttpDocumentSessionClient implements DocumentSessionClient {
  readonly #Api: Client<paths>;
  readonly #BaseUrl: string;
  #Session: SessionResponse | null = null;

  constructor(FetchImplementation: typeof fetch = globalThis.fetch.bind(globalThis), BaseUrl: string = DefaultBaseUrl()) {
    this.#BaseUrl = BaseUrl;
    this.#Api = createClient<paths>({ baseUrl: BaseUrl, credentials: "same-origin", fetch: (Request) => FetchImplementation(Request) });
  }

  async createSession(Input: CreateDocumentSessionInput): Promise<DocumentSessionDetail> {
    await this.#ensureSession();
    return RequireData<DocumentSessionDetail>(await this.#Api.POST("/api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions", {
      body: { base_version_id: Input.BaseVersionId, mode: Input.Mode },
      params: { header: this.#headers(), path: { drive_id: Input.DriveId, node_id: Input.NodeId } },
    }));
  }

  async listOwnSessions(Options: ListDocumentSessionsOptions = {}): Promise<DocumentSessionPage> {
    return RequireData<DocumentSessionPage>(await this.#Api.GET("/api/v1/document-sessions", {
      params: { query: { limit: PageLimit, ...(Options.Cursor === undefined ? {} : { cursor: Options.Cursor }) } },
      ...(Options.Signal === undefined ? {} : { signal: Options.Signal }),
    }));
  }

  async getOwnSession(SessionId: string): Promise<DocumentSessionDetail> {
    return RequireData<DocumentSessionDetail>(await this.#Api.GET("/api/v1/document-sessions/{document_session_id}", {
      params: { path: { document_session_id: SessionId } },
    }));
  }

  async revokeOwnSession(SessionId: string): Promise<void> {
    await this.#ensureSession();
    RequireSuccess(await this.#Api.DELETE("/api/v1/document-sessions/{document_session_id}", {
      params: { header: this.#headers(), path: { document_session_id: SessionId } },
    }));
  }

  async redeemLaunch(SessionId: string): Promise<DocumentSessionLaunchHandoff> {
    await this.#ensureSession();
    return RequireData<DocumentSessionLaunchHandoff>(await this.#Api.POST("/api/v1/document-sessions/{document_session_id}/handoff", {
      params: { header: this.#csrfHeaders(), path: { document_session_id: SessionId } },
    }));
  }

  async listNodeSessions(DriveId: string, NodeId: string, Options: ListDocumentSessionsOptions = {}): Promise<DocumentSessionPage> {
    return RequireData<DocumentSessionPage>(await this.#Api.GET("/api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions", {
      params: { path: { drive_id: DriveId, node_id: NodeId }, query: { limit: PageLimit, ...(Options.Cursor === undefined ? {} : { cursor: Options.Cursor }) } },
      ...(Options.Signal === undefined ? {} : { signal: Options.Signal }),
    }));
  }

  async forceClose(Session: components["schemas"]["DocumentSessionSummary"]): Promise<void> {
    await this.#ensureSession();
    RequireSuccess(await this.#Api.DELETE("/api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions/{document_session_id}", {
      params: { header: this.#headers(), path: { document_session_id: Session.id, drive_id: Session.drive_id, node_id: Session.node_id } },
    }));
  }

  async createConflictCopy(SessionId: string, TargetName: string): Promise<DocumentSessionConflictCopy> {
    await this.#ensureSession();
    const Detail = await this.getOwnSession(SessionId);
    const Source = RequireData<components["schemas"]["Node"]>(await this.#Api.GET("/api/v1/drives/{drive_id}/nodes/{node_id}", {
      params: { path: { drive_id: Detail.session.drive_id, node_id: Detail.session.node_id } },
    }));
    if (Source.parent_id === null) throw new Error("The conflicted file has no writable parent.");
    const Parent = RequireData<components["schemas"]["Node"]>(await this.#Api.GET("/api/v1/drives/{drive_id}/nodes/{node_id}", {
      params: { path: { drive_id: Detail.session.drive_id, node_id: Source.parent_id } },
    }));
    if (Parent.kind !== "directory") throw new Error("The conflicted file parent is unavailable.");
    return RequireData<DocumentSessionConflictCopy>(await this.#Api.POST("/api/v1/document-sessions/{document_session_id}/conflict-copy", {
      body: { expected_parent_generation: Parent.namespace_generation, target_name: TargetName, target_parent_id: Parent.id },
      params: { header: this.#headers(), path: { document_session_id: SessionId } },
    }));
  }

  async #ensureSession(): Promise<void> {
    if (this.#Session !== null) return;
    this.#Session = RequireData<SessionResponse>(await this.#Api.GET("/api/v1/session"));
  }

  #headers(): MutationHeaders {
    return { ...this.#csrfHeaders(), "Idempotency-Key": crypto.randomUUID() };
  }

  #csrfHeaders(): CsrfHeaders {
    if (this.#Session === null) throw new Error("The session is unavailable.");
    return { Origin: new URL(this.#BaseUrl).origin, "Sec-Fetch-Site": "same-origin", "X-FileBelt-Csrf": this.#Session.csrf_token };
  }
}

function DefaultBaseUrl(): string {
  return typeof window === "undefined" ? "https://filebelt.localhost" : window.location.origin;
}

function RequireData<T>(Result: ApiResult<unknown>): T {
  if (Result.response.ok && Result.data !== undefined) return Result.data as T;
  throw RequestError(Result.response, Result.error);
}

function RequireSuccess(Result: ApiResult<unknown>): void {
  if (!Result.response.ok) throw RequestError(Result.response, Result.error);
}

function RequestError(Response: Response, ErrorValue: unknown): Error {
  if (Response.status === 401) return new AuthenticationRequiredError();
  const Title = typeof ErrorValue === "object" && ErrorValue !== null && "title" in ErrorValue && typeof ErrorValue.title === "string" ? ErrorValue.title : null;
  return new Error(Title ?? `FileBelt request failed (${Response.status}).`);
}
