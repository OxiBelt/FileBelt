// SPDX-License-Identifier: Apache-2.0

import createClient from "openapi-fetch";
import type { Client } from "openapi-fetch";

import { AuthenticationRequiredError } from "./client.js";
import type {
  CreateShareInput,
  FileBeltClient,
  PublicShareClient,
  PublicShareGrant,
} from "./client.js";
import type { components, paths } from "./generated/openapi.js";
import type {
  FileEntry,
  SessionRecord,
  ShareRecord,
  UploadCandidate,
  VersionRecord,
  WorkspaceSnapshot,
} from "./model.js";

type SessionResponse = components["schemas"]["Session"];
type SessionSummaryResponse = components["schemas"]["SessionSummary"];
type DriveResponse = components["schemas"]["Drive"];
type NodeResponse = components["schemas"]["Node"];
type VersionResponse = components["schemas"]["FileVersion"];
type ShareResponse = components["schemas"]["DirectShare"];
type UploadAllocation = components["schemas"]["UploadAllocation"];
type ByteGrant = components["schemas"]["ByteGrant"];
type UploadGrants = components["schemas"]["UploadGrants"];
type DownloadGrant = components["schemas"]["DownloadGrant"];
type DrivePage = components["schemas"]["DrivePage"];
type NodePage = components["schemas"]["NodePage"];
type VersionPage = components["schemas"]["VersionPage"];

interface NodeLocation {
  driveId: string;
  headVersionId: string | null;
  namespaceGeneration: number;
  parentId: string | null;
}

interface DirectShareLocation {
  driveId: string;
  nodeId: string;
  principalId: string;
}

interface Page<T> {
  readonly items: readonly T[];
  readonly next_cursor: string | null;
}

interface ApiResult<T> {
  readonly data?: T;
  readonly error?: unknown;
  readonly response: Response;
}

interface MutationHeaders {
  Origin: string;
  "Sec-Fetch-Site": "same-origin";
  "X-FileBelt-Csrf": string;
}

class ApiRequestError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
  }
}

const pageLimit = 200;

/** Same-origin production adapter for the generated FileBelt HTTP contract. */
export class HttpFileBeltClient implements FileBeltClient, PublicShareClient {
  readonly #api: Client<paths>;
  readonly #baseUrl: string;
  readonly #fetch: typeof fetch;
  readonly #locations = new Map<string, NodeLocation>();
  readonly #shares = new Map<string, DirectShareLocation>();
  readonly #versions = new Map<string, { driveId: string; nodeId: string }>();
  #session: SessionResponse | null = null;
  #uploadTarget: { driveId: string; namespaceGeneration: number; rootId: string } | null = null;

  constructor(
    fetchImplementation: typeof fetch = globalThis.fetch.bind(globalThis),
    baseUrl: string = defaultBaseUrl(),
  ) {
    this.#baseUrl = baseUrl;
    this.#fetch = fetchImplementation;
    this.#api = createClient<paths>({
      baseUrl,
      credentials: "same-origin",
      fetch: (request) => this.#fetch(request),
    });
  }

  async getWorkspace(signal?: AbortSignal): Promise<WorkspaceSnapshot> {
    const session = requireData<SessionResponse>(await this.#api.GET("/api/v1/session", signalInit(signal)));
    this.#session = session;
    const drives = await this.#collectPages<DriveResponse>(async (cursor) => requireData<DrivePage>(
      await this.#api.GET("/api/v1/drives", {
        params: { query: pageQuery(cursor) },
        ...signalInit(signal),
      }),
    ));
    const privateDrive = drives.find(({ kind }) => kind === "private") ?? null;
    if (privateDrive === null) {
      this.#uploadTarget = null;
    } else {
      const root = await this.#getNode(privateDrive.id, privateDrive.root_id, signal);
      if (root.kind !== "directory") throw new Error("The private drive root is unavailable.");
      this.#uploadTarget = {
        driveId: privateDrive.id,
        namespaceGeneration: root.namespace_generation,
        rootId: privateDrive.root_id,
      };
    }
    this.#locations.clear();
    this.#shares.clear();
    this.#versions.clear();

    const entries: FileEntry[] = [];
    const versions: VersionRecord[] = [];
    const shares: ShareRecord[] = [];
    for (const drive of drives) {
      const nodes: NodeResponse[] = [];
      const directories = [drive.root_id];
      while (directories.length > 0) {
        const parentId = directories.shift();
        if (parentId === undefined) break;
        const children = await this.#listChildren(drive.id, parentId, signal);
        nodes.push(...children);
        directories.push(...children.filter(({ kind }) => kind === "directory").map(({ id }) => id));
      }
      nodes.push(...await this.#listTrash(drive.id, signal));
      for (const node of nodes) {
        this.#locations.set(node.id, {
          driveId: drive.id,
          headVersionId: node.head_version_id,
          namespaceGeneration: node.namespace_generation,
          parentId: node.parent_id,
        });
        const nodeVersions = node.kind === "file"
          ? await this.#listVersions(drive.id, node.id, signal)
          : [];
        for (const version of nodeVersions) {
          this.#versions.set(version.id, { driveId: drive.id, nodeId: node.id });
          versions.push(versionRecord(version));
        }
        const nodeShares = await this.#optionalShares(drive.id, node.id, signal);
        for (const share of nodeShares) {
          const shareId = crypto.randomUUID();
          this.#shares.set(shareId, {
            driveId: drive.id,
            nodeId: node.id,
            principalId: share.principal_id,
          });
          shares.push({
            id: shareId,
            kind: share.kind,
            permission: sharePermission(share.preset),
            resourceId: node.id,
            resourceName: node.display_name,
            target: share.verified_email,
          });
        }
        entries.push(fileEntry(node, drive.owner_display_name, drive.kind === "shared" || nodeShares.length > 0));
      }
    }

    const knownEntries = new Set(entries.map(({ id }) => id));
    const sharedNodes = await this.#collectPages<NodeResponse>(async (cursor) => requireData<NodePage>(
      await this.#api.GET("/api/v1/shared", {
        params: { query: pageQuery(cursor) },
        ...signalInit(signal),
      }),
    ));
    for (const node of sharedNodes) {
      if (knownEntries.has(node.id)) continue;
      this.#locations.set(node.id, {
        driveId: node.drive_id,
        headVersionId: node.head_version_id,
        namespaceGeneration: node.namespace_generation,
        parentId: node.parent_id,
      });
      if (node.kind === "file") {
        const nodeVersions = await this.#listVersions(node.drive_id, node.id, signal);
        for (const version of nodeVersions) {
          this.#versions.set(version.id, { driveId: node.drive_id, nodeId: node.id });
          versions.push(versionRecord(version));
        }
      }
      entries.push(fileEntry(node, "Owner unavailable", true));
    }

    const sessionResponse = requireData<readonly SessionSummaryResponse[]>(
      await this.#api.GET("/api/v1/sessions", signalInit(signal)),
    );
    const sessions = sessionResponse.map<SessionRecord>((item: SessionSummaryResponse) => ({
      current: item.current,
      device: item.user_agent ?? "Unknown client",
      id: item.id,
      lastActiveAt: item.last_seen_at,
      location: item.current ? "Current device" : "Location unavailable",
    }));

    return {
      admin: {
        drives: drives.filter(({ kind }) => kind === "shared").map((drive) => ({
          id: drive.id,
          name: drive.display_name,
          quotaBytes: drive.quota_bytes,
          usedBytes: drive.used_physical_bytes,
        })),
        groups: [],
        users: [],
      },
      currentUser: {
        displayName: session.display_name,
        email: session.verified_email ?? "",
        isTenantAdmin: session.tenant_admin,
      },
      entries,
      privacy: [],
      sessions,
      shares,
      uploads: [],
      versions,
    };
  }

  async upload(files: readonly UploadCandidate[]): Promise<void> {
    const target = this.#uploadTarget;
    if (target === null) throw new Error("No writable private drive is available.");
    await this.#ensureSession();
    for (const candidate of files) {
      if (candidate.data === undefined || candidate.data.size !== candidate.size) {
        throw new Error("The selected file bytes are unavailable.");
      }
      const root = await this.#getNode(target.driveId, target.rootId);
      if (root.kind !== "directory") throw new Error("The private drive root is unavailable.");
      target.namespaceGeneration = root.namespace_generation;
      const allocation = requireData<UploadAllocation>(await this.#api.POST("/api/v1/drives/{drive_id}/uploads", {
        body: {
          declared_size_bytes: candidate.size,
          expected_parent_generation: target.namespaceGeneration,
          name: candidate.name,
          parent_id: target.rootId,
        },
        params: {
          header: this.#idempotentMutationHeaders(),
          path: { drive_id: target.driveId },
        },
      }));

      let cursor: string | null = null;
      let finalize: ByteGrant | null;
      do {
        const grants: UploadGrants = requireData<UploadGrants>(await this.#api.GET("/api/v1/uploads/{upload_id}", {
          params: {
            path: { upload_id: allocation.upload_id },
            query: pageQuery(cursor),
          },
        }));
        for (let index = 0; index < grants.parts.length; index += 1) {
          const grant = grants.parts[index];
          if (grant === undefined) continue;
          const partNumber = uploadPartNumber(grant.path) ?? index;
          const start = partNumber * allocation.chunk_size_bytes;
          const end = Math.min(start + allocation.chunk_size_bytes, candidate.size);
          await this.#ioRequest(grant.path, {
            body: candidate.data.slice(start, end),
            headers: { Authorization: `fbcap1 ${grant.authorization}` },
            method: "PUT",
          }, "omit");
        }
        finalize = grants.finalize;
        cursor = grants.next_cursor;
      } while (cursor !== null);
      if (finalize === null) throw new Error("The upload finalize grant is unavailable.");
      await this.#ioRequest(finalize.path, {
        headers: { Authorization: `fbcap1 ${finalize.authorization}` },
        method: "POST",
      }, "omit");
      requireSuccess(await this.#api.POST("/api/v1/uploads/{upload_id}/commit", {
        body: { expected_fencing_token: allocation.fencing_token },
        params: {
          header: this.#idempotentMutationHeaders(),
          path: { upload_id: allocation.upload_id },
        },
      }));
    }
  }

  async download(entryId: string): Promise<Blob> {
    const location = this.#location(entryId);
    await this.#ensureSession();
    const grant = requireData<DownloadGrant>(await this.#api.POST(
      "/api/v1/drives/{drive_id}/nodes/{node_id}/download-grants",
      {
        body: { version_id: null },
        params: {
          header: this.#mutationHeaders(),
          path: { drive_id: location.driveId, node_id: entryId },
        },
      },
    ));
    const response = await this.#ioRequest(grant.path, { method: "GET" }, "same-origin");
    return response.blob();
  }

  async trashEntries(entryIds: readonly string[]): Promise<void> {
    await this.#ensureSession();
    for (const entryId of entryIds) {
      const location = this.#location(entryId);
      requireSuccess(await this.#api.POST("/api/v1/drives/{drive_id}/nodes/{node_id}/trash", {
        body: { expected_namespace_generation: location.namespaceGeneration },
        params: {
          header: this.#mutationHeaders(),
          path: { drive_id: location.driveId, node_id: entryId },
        },
      }));
    }
  }

  async restoreEntries(entryIds: readonly string[]): Promise<void> {
    await this.#ensureSession();
    for (const entryId of entryIds) {
      const location = this.#location(entryId);
      requireSuccess(await this.#api.POST("/api/v1/drives/{drive_id}/nodes/{node_id}/restore", {
        body: { expected_namespace_generation: location.namespaceGeneration },
        params: {
          header: this.#mutationHeaders(),
          path: { drive_id: location.driveId, node_id: entryId },
        },
      }));
    }
  }

  async createShare(input: CreateShareInput): Promise<void> {
    if (input.kind !== "direct") {
      throw new Error("This FileBelt version supports direct verified-email shares only.");
    }
    await this.#ensureSession();
    const location = this.#location(input.fileId);
    requireSuccess(await this.#api.POST("/api/v1/drives/{drive_id}/nodes/{node_id}/shares", {
      body: {
        inheritance: "self",
        kind: input.kind,
        preset: sharePreset(input.permission),
        verified_email: input.target,
      },
      params: {
        header: this.#idempotentMutationHeaders(),
        path: { drive_id: location.driveId, node_id: input.fileId },
      },
    }));
  }

  async revokeShare(shareId: string): Promise<void> {
    const location = this.#shares.get(shareId);
    if (location === undefined) throw new Error("The selected share is unavailable.");
    await this.#ensureSession();
    requireSuccess(await this.#api.DELETE(
      "/api/v1/drives/{drive_id}/nodes/{node_id}/shares/{principal_id}",
      {
        params: {
          header: this.#mutationHeaders(),
          path: {
            drive_id: location.driveId,
            node_id: location.nodeId,
            principal_id: location.principalId,
          },
        },
      },
    ));
  }

  async restoreVersion(versionId: string): Promise<void> {
    const location = this.#versions.get(versionId);
    if (location === undefined) throw new Error("The selected version is unavailable.");
    const node = this.#location(location.nodeId);
    if (node.headVersionId === null) throw new Error("The selected file head is unavailable.");
    await this.#ensureSession();
    requireSuccess(await this.#api.POST(
      "/api/v1/drives/{drive_id}/nodes/{node_id}/versions/{version_id}/restore",
      {
        body: { expected_head_version_id: node.headVersionId },
        params: {
          header: this.#idempotentMutationHeaders(),
          path: {
            drive_id: location.driveId,
            node_id: location.nodeId,
            version_id: versionId,
          },
        },
      },
    ));
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.#ensureSession();
    requireSuccess(await this.#api.DELETE("/api/v1/sessions/{session_id}", {
      params: {
        header: this.#mutationHeaders(),
        path: { session_id: sessionId },
      },
    }));
  }

  async markPrivacyRead(): Promise<void> {
    throw new Error("Privacy notification updates are not available in this release.");
  }

  async suspendUser(): Promise<void> {
    throw new Error("Tenant user administration is not available in this release.");
  }

  async createGroup(): Promise<void> {
    throw new Error("Group administration is not available in this release.");
  }

  async createSharedDrive(): Promise<void> {
    throw new Error("Shared-drive administration is not available in this release.");
  }

  async exchangePublicShare(): Promise<PublicShareGrant> {
    throw new Error("Anonymous share links are not available in this release.");
  }

  async downloadPublic(): Promise<Blob> {
    throw new Error("Anonymous share links are not available in this release.");
  }

  #location(entryId: string): NodeLocation {
    const location = this.#locations.get(entryId);
    if (location === undefined) throw new Error("The selected resource is unavailable.");
    return location;
  }

  async #collectPages<T>(loadPage: (cursor: string | null) => Promise<Page<T>>): Promise<T[]> {
    const items: T[] = [];
    let cursor: string | null = null;
    do {
      const page = await loadPage(cursor);
      items.push(...page.items);
      cursor = page.next_cursor;
    } while (cursor !== null);
    return items;
  }

  async #getNode(driveId: string, nodeId: string, signal?: AbortSignal): Promise<NodeResponse> {
    return requireData<NodeResponse>(await this.#api.GET("/api/v1/drives/{drive_id}/nodes/{node_id}", {
      params: { path: { drive_id: driveId, node_id: nodeId } },
      ...signalInit(signal),
    }));
  }

  async #listChildren(driveId: string, nodeId: string, signal?: AbortSignal): Promise<NodeResponse[]> {
    return this.#collectPages(async (cursor) => requireData<NodePage>(await this.#api.GET(
      "/api/v1/drives/{drive_id}/nodes/{node_id}/children",
      {
        params: {
          path: { drive_id: driveId, node_id: nodeId },
          query: pageQuery(cursor),
        },
        ...signalInit(signal),
      },
    )));
  }

  async #listTrash(driveId: string, signal?: AbortSignal): Promise<NodeResponse[]> {
    return this.#collectPages(async (cursor) => requireData<NodePage>(await this.#api.GET(
      "/api/v1/drives/{drive_id}/trash",
      {
        params: {
          path: { drive_id: driveId },
          query: pageQuery(cursor),
        },
        ...signalInit(signal),
      },
    )));
  }

  async #listVersions(driveId: string, nodeId: string, signal?: AbortSignal): Promise<VersionResponse[]> {
    return this.#collectPages(async (cursor) => requireData<VersionPage>(await this.#api.GET(
      "/api/v1/drives/{drive_id}/nodes/{node_id}/versions",
      {
        params: {
          path: { drive_id: driveId, node_id: nodeId },
          query: pageQuery(cursor),
        },
        ...signalInit(signal),
      },
    )));
  }

  async #optionalShares(driveId: string, nodeId: string, signal?: AbortSignal): Promise<readonly ShareResponse[]> {
    const result = await this.#api.GET("/api/v1/drives/{drive_id}/nodes/{node_id}/shares", {
      params: { path: { drive_id: driveId, node_id: nodeId } },
      ...signalInit(signal),
    });
    if (result.response.status === 404) return [];
    return requireData<readonly ShareResponse[]>(result);
  }

  async #ensureSession(): Promise<SessionResponse> {
    if (this.#session !== null) return this.#session;
    this.#session = requireData<SessionResponse>(await this.#api.GET("/api/v1/session"));
    return this.#session;
  }

  #mutationHeaders(): MutationHeaders {
    if (this.#session === null) throw new Error("The session is unavailable.");
    return {
      Origin: new URL(this.#baseUrl).origin,
      "Sec-Fetch-Site": "same-origin",
      "X-FileBelt-Csrf": this.#session.csrf_token,
    };
  }

  #idempotentMutationHeaders(): MutationHeaders & { "Idempotency-Key": string } {
    return { ...this.#mutationHeaders(), "Idempotency-Key": crypto.randomUUID() };
  }

  async #ioRequest(
    path: string,
    init: RequestInit,
    credentials: RequestCredentials,
  ): Promise<Response> {
    const request = new Request(new URL(path, this.#baseUrl), { ...init, credentials });
    const response = await this.#fetch(request);
    if (response.ok) return response;
    let problem: unknown;
    try {
      problem = await response.json();
    } catch {
      problem = undefined;
    }
    throw requestError(response, problem);
  }
}

function defaultBaseUrl(): string {
  return typeof window === "undefined" ? "https://filebelt.localhost" : window.location.origin;
}

function fileEntry(node: NodeResponse, owner: string, shared: boolean): FileEntry {
  return {
    id: node.id,
    kind: node.kind === "directory" ? "folder" : "file",
    modifiedAt: node.updated_at,
    name: node.display_name,
    owner,
    shared,
    size: node.size_bytes,
    status: "ready",
    trashed: node.trashed,
    version: node.version_ordinal ?? 0,
  };
}

function pageQuery(cursor: string | null): { cursor?: string; limit: number } {
  return cursor === null ? { limit: pageLimit } : { cursor, limit: pageLimit };
}

function requireData<T>(result: ApiResult<unknown>): T {
  if (result.response.ok && result.data !== undefined) return result.data as T;
  throw requestError(result.response, result.error);
}

function requireSuccess(result: ApiResult<unknown>): void {
  if (!result.response.ok) throw requestError(result.response, result.error);
}

function requestError(response: Response, error: unknown): Error {
  if (response.status === 401) return new AuthenticationRequiredError();
  return new ApiRequestError(
    response.status,
    problemTitle(error) ?? `FileBelt request failed (${response.status}).`,
  );
}

function problemTitle(value: unknown): string | null {
  if (typeof value !== "object" || value === null || !("title" in value)) return null;
  return typeof value.title === "string" ? value.title : null;
}

function uploadPartNumber(path: string): number | null {
  const match = /\/parts\/(\d+)$/.exec(path);
  if (match?.[1] === undefined) return null;
  const value = Number.parseInt(match[1], 10);
  return Number.isSafeInteger(value) ? value : null;
}

function signalInit(signal: AbortSignal | undefined): { signal?: AbortSignal } {
  return signal === undefined ? {} : { signal };
}

function sharePermission(preset: ShareResponse["preset"]): ShareRecord["permission"] {
  switch (preset) {
    case "contributor": return "Contributor";
    case "manager": return "Manager";
    case "viewer": return "Viewer";
  }
}

function sharePreset(permission: ShareRecord["permission"]): ShareResponse["preset"] {
  switch (permission) {
    case "Contributor": return "contributor";
    case "Manager": return "manager";
    case "Viewer": return "viewer";
  }
}

function versionRecord(version: VersionResponse): VersionRecord {
  return {
    author: version.created_by,
    createdAt: version.created_at,
    fileId: version.node_id,
    id: version.id,
    size: version.size_bytes,
    version: version.ordinal,
  };
}
