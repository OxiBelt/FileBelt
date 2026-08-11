// SPDX-License-Identifier: Apache-2.0

import createClient from "openapi-fetch";
import type { Client } from "openapi-fetch";

import type {
  NfsAdminClient,
  NfsAdminSnapshot,
  NfsExportRegistration,
  NfsExportState,
  NfsFeatureState,
  NfsMappingUpsert,
  NfsPosixGroupRegistration,
} from "@filebelt/admin";

import { AuthenticationRequiredError } from "./client.js";
import type { components, paths } from "./generated/openapi.js";

type SessionResponse = components["schemas"]["Session"];
type NfsOverviewResponse = components["schemas"]["NfsAdminOverview"];
type NfsConflictResponse = components["schemas"]["NfsWriteConflict"];
type NfsConflictCopyInput = Parameters<NfsAdminClient["copyConflict"]>[1];

export class NfsReauthenticationRequiredError extends Error {
  constructor() {
    super("Recent tenant administrator authentication is required.");
    this.name = "NfsReauthenticationRequiredError";
  }
}

interface ApiResult<T> {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly data?: T;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly error?: unknown;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly response: Response;
}

interface MutationHeaders {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- FileBelt HTTP requests require this exact idempotency header name.
  "Idempotency-Key": string;
  Origin: string;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- HTTP requires this exact Fetch Metadata header name.
  "Sec-Fetch-Site": "same-origin";
  // eslint-disable-next-line @typescript-eslint/naming-convention -- FileBelt HTTP requests require this exact CSRF header name.
  "X-FileBelt-Csrf": string;
}

type SignalInitShape = {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Fetch `RequestInit` exposes this exact abort-signal key.
  signal?: AbortSignal;
};

/** Same-origin adapter for generation-fenced tenant NFS administration. */
export class HttpNfsAdminClient implements NfsAdminClient {
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

  async getOverview(Signal?: AbortSignal): Promise<NfsAdminSnapshot> {
    const [OverviewResult, ConflictsResult] = await Promise.all([
      this.#Api.GET("/api/v1/admin/mounts/nfs", SignalInit(Signal)),
      this.#Api.GET("/api/v1/admin/mounts/nfs/conflicts", SignalInit(Signal)),
    ]);
    return Snapshot(
      RequireData<NfsOverviewResponse>(OverviewResult),
      RequireData<NfsConflictResponse[]>(ConflictsResult),
    );
  }

  async transitionFeature(ExpectedGeneration: number, TargetState: NfsFeatureState, ConfirmTenant: string): Promise<void> {
    RequireData(await this.#Api.PUT("/api/v1/admin/mounts/nfs/feature", {
      body: { confirm_tenant: ConfirmTenant, expected_generation: ExpectedGeneration, target_state: TargetState },
      params: { header: await this.#mutationHeaders() },
    }));
  }

  async registerExport(Input: NfsExportRegistration, ConfirmTenant: string): Promise<void> {
    RequireData(await this.#Api.POST("/api/v1/admin/mounts/nfs/exports", {
      body: { confirm_tenant: ConfirmTenant, drive_id: Input.DriveId, export_id: Input.ExportId },
      params: { header: await this.#mutationHeaders() },
    }));
  }

  async transitionExport(
    DriveId: string,
    ExpectedGeneration: number,
    TargetState: NfsExportState,
    ConfirmTenant: string,
  ): Promise<void> {
    RequireData(await this.#Api.PUT("/api/v1/admin/mounts/nfs/exports/{drive_id}", {
      body: { confirm_tenant: ConfirmTenant, expected_generation: ExpectedGeneration, target_state: TargetState },
      params: {
        header: await this.#mutationHeaders(),
        path: { drive_id: DriveId },
      },
    }));
  }

  async registerPosixGroup(Input: NfsPosixGroupRegistration, ConfirmTenant: string): Promise<void> {
    RequireData(await this.#Api.POST("/api/v1/admin/mounts/nfs/posix-groups", {
      body: {
        confirm_tenant: ConfirmTenant,
        group_id: Input.GroupId,
        posix_name: Input.PosixName,
        projected_gid: Input.ProjectedGid,
      },
      params: { header: await this.#mutationHeaders() },
    }));
  }

  async upsertMapping(Input: NfsMappingUpsert, ConfirmTenant: string): Promise<void> {
    RequireData(await this.#Api.POST("/api/v1/admin/mounts/nfs/mappings", {
      body: {
        allowed_drive_ids: Input.AllowedDriveIds,
        confirm_tenant: ConfirmTenant,
        expected_generation: Input.ExpectedGeneration,
        kerberos_principal: Input.KerberosPrincipal,
        principal_id: Input.PrincipalId,
        projected_gid: Input.ProjectedGid,
        projected_uid: Input.ProjectedUid,
      },
      params: { header: await this.#mutationHeaders() },
    }));
  }

  async revokeMapping(CredentialId: string, ExpectedGeneration: number, ConfirmTenant: string): Promise<void> {
    RequireSuccess(await this.#Api.DELETE("/api/v1/admin/mounts/nfs/mappings/{credential_id}", {
      params: {
        header: await this.#mutationHeaders(),
        path: { credential_id: CredentialId },
        query: { confirm_tenant: ConfirmTenant, expected_generation: ExpectedGeneration },
      },
    }));
  }

  async copyConflict(ConflictId: string, Input: NfsConflictCopyInput, ConfirmTenant: string): Promise<void> {
    RequireData(await this.#Api.POST("/api/v1/admin/mounts/nfs/conflicts/{conflict_id}/copy", {
      body: {
        confirm_tenant: ConfirmTenant,
        display_name: Input.DisplayName,
        drive_id: Input.DriveId,
        expected_parent_generation: Input.ExpectedParentGeneration,
        parent_id: Input.ParentId,
      },
      params: {
        header: await this.#mutationHeaders(),
        path: { conflict_id: ConflictId },
      },
    }));
  }

  async discardConflict(ConflictId: string, ConfirmTenant: string): Promise<void> {
    RequireSuccess(await this.#Api.DELETE("/api/v1/admin/mounts/nfs/conflicts/{conflict_id}", {
      params: {
        header: await this.#mutationHeaders(),
        path: { conflict_id: ConflictId },
        query: { confirm_tenant: ConfirmTenant },
      },
    }));
  }

  async #mutationHeaders(): Promise<MutationHeaders> {
    if (this.#CsrfToken === null) {
      const Session = RequireData<SessionResponse>(await this.#Api.GET("/api/v1/session"));
      this.#CsrfToken = Session.csrf_token;
    }
    return {
      "Idempotency-Key": crypto.randomUUID(),
      Origin: this.#Origin,
      "Sec-Fetch-Site": "same-origin",
      "X-FileBelt-Csrf": this.#CsrfToken,
    };
  }
}

function Snapshot(Response: NfsOverviewResponse, Conflicts: NfsConflictResponse[]): NfsAdminSnapshot {
  return {
    Conflicts: Conflicts.map((Conflict) => ({
      BaseVersionId: Conflict.base_version_id,
      ConflictCopyNodeId: Conflict.conflict_copy_node_id,
      ConflictCopyVersionId: Conflict.conflict_copy_version_id,
      CreatedAt: Conflict.created_at,
      DriveId: Conflict.drive_id,
      ExpectedHeadVersionId: Conflict.expected_head_version_id,
      ExpiresAt: Conflict.expires_at,
      Id: Conflict.id,
      LogicalSizeBytes: Conflict.logical_size_bytes,
      ObservedHeadVersionId: Conflict.observed_head_version_id,
      SourceNodeId: Conflict.source_node_id,
      State: Conflict.state,
      WriteSessionId: Conflict.write_session_id,
    })),
    Exports: Response.exports.map((Export) => ({
      AppliedGeneration: Export.applied_generation,
      AppliedState: Export.applied_state,
      DesiredGeneration: Export.desired_generation,
      DesiredState: Export.desired_state,
      DriveId: Export.drive_id,
      ExportId: Export.export_id,
      ExportPath: Export.export_path,
      InSync: Export.in_sync,
    })),
    Feature: {
      AppliedGatewayEpoch: Response.feature.applied_gateway_epoch,
      AppliedGatewayId: Response.feature.applied_gateway_id,
      AppliedManifestGeneration: Response.feature.applied_manifest_generation,
      DesiredManifestGeneration: Response.feature.desired_manifest_generation,
      Generation: Response.feature.generation,
      ManifestApplied: Response.feature.manifest_applied,
      RestoreGeneration: Response.feature.restore_generation,
      State: Response.feature.state,
    },
    Mappings: Response.mappings.map((Mapping) => ({
      ...(Mapping.allowed_drive_ids === undefined ? {} : { AllowedDriveIds: Mapping.allowed_drive_ids }),
      CredentialId: Mapping.credential_id,
      Generation: Mapping.generation,
      KerberosPrincipal: Mapping.kerberos_principal,
      PrincipalId: Mapping.principal_id,
      ProjectedGid: Mapping.projected_gid,
      ProjectedUid: Mapping.projected_uid,
    })),
    PosixGroups: Response.posix_groups.map((Group) => ({
      GroupId: Group.group_id,
      PosixName: Group.posix_name,
      ProjectedGid: Group.projected_gid,
    })),
    Realm: Response.realm,
    TenantSlug: Response.tenant_slug,
  };
}

function DefaultBaseUrl(): string {
  return typeof window === "undefined" ? "https://filebelt.localhost" : window.location.origin;
}

function SignalInit(Signal?: AbortSignal): SignalInitShape {
  return Signal === undefined ? {} : { signal: Signal };
}

function RequireData<T>(Result: ApiResult<unknown>): T {
  if (Result.response.ok && Result.data !== undefined) return Result.data as T;
  throw RequestError(Result);
}

function RequireSuccess(Result: ApiResult<unknown>): void {
  if (!Result.response.ok) throw RequestError(Result);
}

function RequestError(Result: ApiResult<unknown>): Error {
  if (Result.response.status === 401) return new AuthenticationRequiredError();
  if (ProblemCode(Result.error) === "admin.reauthentication_required") {
    return new NfsReauthenticationRequiredError();
  }
  const Title = ProblemTitle(Result.error);
  return new Error(Title ?? `FileBelt NFS administration request failed (${Result.response.status}).`);
}

function ProblemCode(Value: unknown): string | null {
  if (typeof Value !== "object" || Value === null || !("code" in Value)) return null;
  return typeof Value.code === "string" ? Value.code : null;
}

function ProblemTitle(Value: unknown): string | null {
  if (typeof Value !== "object" || Value === null || !("title" in Value)) return null;
  return typeof Value.title === "string" ? Value.title : null;
}
