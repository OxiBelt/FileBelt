// SPDX-License-Identifier: Apache-2.0

import createClient from "openapi-fetch";
import type { Client } from "openapi-fetch";

import type {
  AdminMcpBlockRuleView,
  AdminMcpServiceIdentityView,
  AdminMcpTemplateView,
  CreateMcpRegistrationInput,
  McpActivityView,
  McpCapabilityReviewView,
  McpInvocationEventView,
  McpInvocationInput,
  McpPreparedInvocation,
  McpRegistrationView,
  McpSettingsClient,
  McpSettingsSnapshot,
} from "@filebelt/mcp-settings";

import { AuthenticationRequiredError } from "./client.js";
import type { components, paths } from "./generated/openapi.js";

type RegistrationResponse = components["schemas"]["McpRegistration"];
type RegistrationPage = components["schemas"]["McpRegistrationPage"];
type CapabilityReviewResponse = components["schemas"]["McpCapabilityReview"];
type CapabilitySnapshotResponse = components["schemas"]["McpCapabilitySnapshot"];
type ActivityPage = components["schemas"]["McpActivityPage"];
type AdminTemplatePage = components["schemas"]["AdminMcpTemplatePage"];
type AdminServicePage = components["schemas"]["AdminMcpServiceIdentityPage"];
type AdminBlockRuleResponse = components["schemas"]["AdminMcpBlockRule"];
type InvocationRequest = components["schemas"]["McpInvocationRequest"];
type InvocationIntent = components["schemas"]["McpInvocationIntent"];
type InvocationEvent = components["schemas"]["McpInvocationEvent"];
type SessionResponse = components["schemas"]["Session"];

interface ApiResult<T> {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly data?: T;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly error?: unknown;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- `openapi-fetch` returns this exact result key.
  readonly response: Response;
}

type MutationHeaders = Record<string, string> & {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- HTTP uses this exact header name.
  "Idempotency-Key": string;
  Origin: string;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Fetch Metadata uses this exact header name.
  "Sec-Fetch-Site": "same-origin";
  // eslint-disable-next-line @typescript-eslint/naming-convention -- FileBelt uses this exact CSRF header name.
  "X-FileBelt-Csrf": string;
};

type VersionedMutationHeaders = MutationHeaders & {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- HTTP uses this exact precondition header name.
  "If-Match": string;
};

const PageQuery = { limit: 200 } as const;

export class HttpMcpSettingsClient implements McpSettingsClient {
  readonly #Api: Client<paths>;
  readonly #BaseUrl: string;
  readonly #Fetch: typeof fetch;
  readonly #Origin: string;
  #CsrfToken: string | null = null;

  constructor(
    FetchImplementation: typeof fetch = globalThis.fetch.bind(globalThis),
    BaseUrl: string = DefaultBaseUrl(),
  ) {
    this.#BaseUrl = BaseUrl;
    this.#Fetch = FetchImplementation;
    this.#Origin = new URL(BaseUrl).origin;
    this.#Api = createClient<paths>({
      baseUrl: BaseUrl,
      credentials: "same-origin",
      fetch: (Request) => this.#Fetch(Request),
    });
  }

  async getSnapshot(IsTenantAdmin: boolean, Signal?: AbortSignal): Promise<McpSettingsSnapshot> {
    await this.#ensureSession(Signal);
    const SignalInit = Signal === undefined ? {} : { signal: Signal };
    const [Registrations, Activity, Templates, Services, BlockRules] = await Promise.all([
      this.#Api.GET("/api/v1/mcp/registrations", { params: { query: PageQuery }, ...SignalInit }),
      this.#Api.GET("/api/v1/mcp/activity", { params: { query: PageQuery }, ...SignalInit }),
      IsTenantAdmin
        ? this.#Api.GET("/api/v1/admin/mcp/templates", {
            params: { query: PageQuery },
            ...SignalInit,
          })
        : null,
      IsTenantAdmin
        ? this.#Api.GET("/api/v1/admin/mcp/service-identities", {
            params: { query: PageQuery },
            ...SignalInit,
          })
        : null,
      IsTenantAdmin ? this.#Api.GET("/api/v1/admin/mcp/block-rules", SignalInit) : null,
    ]);
    return {
      Activity: RequireData<ActivityPage>(Activity).items.map(ActivityView),
      BlockRules:
        BlockRules === null
          ? []
          : RequireData<readonly AdminBlockRuleResponse[]>(BlockRules).map(BlockRuleView),
      Registrations: RequireData<RegistrationPage>(Registrations).items.map(RegistrationView),
      ServiceIdentities:
        Services === null ? [] : RequireData<AdminServicePage>(Services).items.map(ServiceView),
      Templates:
        Templates === null ? [] : RequireData<AdminTemplatePage>(Templates).items.map(TemplateView),
    };
  }

  async createRegistration(Input: CreateMcpRegistrationInput): Promise<void> {
    RequireSuccess(
      await this.#Api.POST("/api/v1/mcp/registrations", {
        body: {
          attachment_policy: {
            allowed_encodings: ["utf8"],
            allowed_mime_patterns: ["text/*", "application/json"],
            max_attachments: 4,
            max_item_bytes: 1_048_576,
            max_total_bytes: 4_194_304,
          },
          display_name: Input.DisplayName,
          endpoint_uri: Input.EndpointUri,
          transport: "streamable_http",
          trust_profile: Input.TrustProfile,
        },
        params: { header: await this.#mutationHeaders() },
      }),
    );
  }

  async importRegistration(Document: string): Promise<void> {
    let Parsed: unknown;
    try {
      Parsed = JSON.parse(Document) as unknown;
    } catch {
      throw new Error("The MCP registration JSON is invalid.");
    }
    RequireSuccess(
      await this.#Api.POST("/api/v1/mcp/registrations/import", {
        body: RegistrationExport(Parsed),
        params: { header: await this.#mutationHeaders() },
      }),
    );
  }

  async exportRegistration(RegistrationId: string): Promise<string> {
    const Value = RequireData<components["schemas"]["McpRegistrationExport"]>(
      await this.#Api.GET("/api/v1/mcp/registrations/{registration_id}/export", {
        params: { path: { registration_id: RegistrationId } },
      }),
    );
    return `${JSON.stringify(Value, null, 2)}\n`;
  }

  async deleteRegistration(Registration: McpRegistrationView): Promise<void> {
    RequireSuccess(
      await this.#Api.DELETE("/api/v1/mcp/registrations/{registration_id}", {
        params: {
          header: await this.#versionedHeaders(Registration.Etag),
          path: { registration_id: Registration.Id },
        },
      }),
    );
  }

  async changeRegistrationState(
    Registration: McpRegistrationView,
    Action: "disable" | "enable" | "revoke",
  ): Promise<void> {
    RequireSuccess(
      await this.#Api.POST("/api/v1/mcp/registrations/{registration_id}/state", {
        body: { action: Action },
        params: {
          header: await this.#versionedHeaders(Registration.Etag),
          path: { registration_id: Registration.Id },
        },
      }),
    );
  }

  async testRegistration(Registration: McpRegistrationView): Promise<boolean> {
    const Result = RequireData<components["schemas"]["McpTestResult"]>(
      await this.#Api.POST("/api/v1/mcp/registrations/{registration_id}/test", {
        params: {
          header: await this.#versionedHeaders(Registration.Etag),
          path: { registration_id: Registration.Id },
        },
      }),
    );
    return Result.succeeded;
  }

  async putCredential(
    Registration: McpRegistrationView,
    Kind: "api_key" | "bearer",
    Secret: string,
  ): Promise<void> {
    RequireSuccess(
      await this.#Api.PUT("/api/v1/mcp/registrations/{registration_id}/credentials", {
        body: { kind: Kind, secret: Secret },
        params: {
          header: await this.#versionedHeaders(Registration.Etag),
          path: { registration_id: Registration.Id },
        },
      }),
    );
  }

  async startOauth(Registration: McpRegistrationView): Promise<string> {
    const Result = RequireData<components["schemas"]["McpOauthStart"]>(
      await this.#Api.POST("/api/v1/mcp/registrations/{registration_id}/oauth/start", {
        body: { return_path: `/settings/mcp/${Registration.Id}` },
        params: {
          header: await this.#versionedHeaders(Registration.Etag),
          path: { registration_id: Registration.Id },
        },
      }),
    );
    return Result.authorization_url;
  }

  async getCapabilityReview(RegistrationId: string): Promise<McpCapabilityReviewView | null> {
    const Result = await this.#Api.GET(
      "/api/v1/mcp/registrations/{registration_id}/capability-review",
      {
        params: { path: { registration_id: RegistrationId } },
      },
    );
    if (Result.response.status === 404) return null;
    return CapabilityReviewView(RequireData<CapabilityReviewResponse>(Result));
  }

  async discoverCapabilities(Registration: McpRegistrationView): Promise<McpCapabilityReviewView> {
    const Snapshot = RequireData<CapabilitySnapshotResponse>(
      await this.#Api.POST("/api/v1/mcp/registrations/{registration_id}/discover", {
        params: {
          header: await this.#versionedHeaders(Registration.Etag),
          path: { registration_id: Registration.Id },
        },
      }),
    );
    return CapabilityReviewView({ decisions: [], reviewed_at: null, snapshot: Snapshot });
  }

  async putCapabilityReview(
    Registration: McpRegistrationView,
    Review: McpCapabilityReviewView,
  ): Promise<void> {
    RequireSuccess(
      await this.#Api.PUT("/api/v1/mcp/registrations/{registration_id}/capability-review", {
        body: {
          decisions: Review.Capabilities.map(({ Fingerprint }) => ({
            capability_fingerprint: Fingerprint,
            decision: Review.Decisions[Fingerprint] ?? "blocked",
          })),
          snapshot_fingerprint: Review.SnapshotFingerprint,
          snapshot_id: Review.SnapshotId,
        },
        params: {
          header: await this.#versionedHeaders(Registration.Etag),
          path: { registration_id: Registration.Id },
        },
      }),
    );
  }

  async createInvocationIntent(Input: McpInvocationInput): Promise<McpPreparedInvocation> {
    const Body = InvocationRequest(Input);
    const Intent = RequireData<InvocationIntent>(
      await this.#Api.POST("/api/v1/mcp/invocation-intents", {
        body: Body,
        params: { header: await this.#mutationHeaders() },
      }),
    );
    return {
      Input,
      Intent: { ExpiresAt: Intent.expires_at, Id: Intent.id, RequestDigest: Intent.request_digest },
    };
  }

  async approveAndInvoke(
    Prepared: McpPreparedInvocation,
    OnEvent: (Event: McpInvocationEventView) => void,
    Signal?: AbortSignal,
  ): Promise<void> {
    const Body = InvocationRequest(Prepared.Input);
    RequireSuccess(
      await this.#Api.POST("/api/v1/mcp/invocation-intents/{intent_id}/approval", {
        body: { expires_at: null, scope: "once" },
        params: { header: await this.#mutationHeaders(), path: { intent_id: Prepared.Intent.Id } },
        ...(Signal === undefined ? {} : { signal: Signal }),
      }),
    );
    const Headers = await this.#streamHeaders();
    const Response = await this.#Fetch(
      new Request(
        new URL(`/api/v1/mcp/invocation-intents/${Prepared.Intent.Id}/stream`, this.#BaseUrl),
        {
          body: JSON.stringify(Body),
          credentials: "same-origin",
          headers: {
            ...Headers,
            Accept: "application/x-ndjson",
            "Content-Type": "application/json",
          },
          method: "POST",
          signal: Signal ?? null,
        },
      ),
    );
    if (!Response.ok || Response.body === null) throw await RequestError(Response);
    const Reader = Response.body.pipeThrough(new TextDecoderStream()).getReader();
    let Pending = "";
    for (;;) {
      const Chunk = await Reader.read();
      Pending += Chunk.value ?? "";
      let Newline = Pending.indexOf("\n");
      while (Newline >= 0) {
        const Line = Pending.slice(0, Newline).trim();
        Pending = Pending.slice(Newline + 1);
        if (Line.length > 0) OnEvent(InvocationEventView(JSON.parse(Line) as InvocationEvent));
        Newline = Pending.indexOf("\n");
      }
      if (Chunk.done) break;
    }
    if (Pending.trim().length > 0)
      OnEvent(InvocationEventView(JSON.parse(Pending) as InvocationEvent));
  }

  async cancelInvocation(InvocationId: string): Promise<void> {
    RequireSuccess(
      await this.#Api.DELETE("/api/v1/mcp/invocations/{invocation_id}", {
        params: { header: await this.#mutationHeaders(), path: { invocation_id: InvocationId } },
      }),
    );
  }

  async createTemplate(
    DisplayName: string,
    EndpointUri: string,
    TrustProfile: string,
  ): Promise<void> {
    RequireSuccess(
      await this.#Api.POST("/api/v1/admin/mcp/templates", {
        body: {
          display_name: DisplayName,
          endpoint_uri: EndpointUri,
          transport: "streamable_http",
          trust_profile: TrustProfile,
        },
        params: { header: await this.#mutationHeaders() },
      }),
    );
  }

  async assignTemplate(
    Template: AdminMcpTemplateView,
    PrincipalId: string,
    PrincipalKind: "group" | "service" | "user",
  ): Promise<void> {
    RequireSuccess(
      await this.#Api.PUT("/api/v1/admin/mcp/templates/{template_id}/assignments/{principal_id}", {
        body: { principal_kind: PrincipalKind },
        params: {
          header: await this.#versionedHeaders(Template.Etag),
          path: { principal_id: PrincipalId, template_id: Template.Id },
        },
      }),
    );
  }

  async createServiceIdentity(DisplayName: string, SpiffeUri: string): Promise<void> {
    RequireSuccess(
      await this.#Api.POST("/api/v1/admin/mcp/service-identities", {
        body: { display_name: DisplayName, spiffe_uri: SpiffeUri },
        params: { header: await this.#mutationHeaders() },
      }),
    );
  }

  async createServiceInvocationGrant(
    Service: AdminMcpServiceIdentityView,
    RegistrationId: string,
    CapabilityKind: "prompt" | "resource" | "tool",
    CapabilityName: string,
    CapabilityFingerprint: string,
    ApplicationId: string,
    ExpiresAt: string,
  ): Promise<void> {
    RequireSuccess(
      await this.#Api.POST("/api/v1/admin/mcp/service-identities/{service_id}/invocation-grants", {
        body: {
          application_id: ApplicationId,
          argument_constraints: {},
          capability: {
            fingerprint: CapabilityFingerprint,
            kind: CapabilityKind,
            name: CapabilityName,
          },
          expires_at: ExpiresAt,
          max_invocations_per_hour: 60,
          mcp_data_grant_ids: [],
          registration_id: RegistrationId,
        },
        params: {
          header: await this.#versionedHeaders(Service.Etag),
          path: { service_id: Service.Id },
        },
      }),
    );
  }

  async createBlockRule(
    Kind: AdminMcpBlockRuleView["Kind"],
    Value: string,
    Reason: string,
  ): Promise<void> {
    RequireSuccess(
      await this.#Api.POST("/api/v1/admin/mcp/block-rules", {
        body: { kind: Kind, reason: Reason, value: Value },
        params: { header: await this.#mutationHeaders() },
      }),
    );
  }

  async #ensureSession(Signal?: AbortSignal): Promise<void> {
    if (this.#CsrfToken !== null) return;
    const Session = RequireData<SessionResponse>(
      await this.#Api.GET("/api/v1/session", Signal === undefined ? {} : { signal: Signal }),
    );
    this.#CsrfToken = Session.csrf_token;
  }

  async #mutationHeaders(): Promise<MutationHeaders> {
    await this.#ensureSession();
    if (this.#CsrfToken === null) throw new AuthenticationRequiredError();
    return {
      "Idempotency-Key": crypto.randomUUID(),
      Origin: this.#Origin,
      "Sec-Fetch-Site": "same-origin",
      "X-FileBelt-Csrf": this.#CsrfToken,
    };
  }

  async #versionedHeaders(Etag: string): Promise<VersionedMutationHeaders> {
    return { ...(await this.#mutationHeaders()), "If-Match": Etag };
  }

  async #streamHeaders(): Promise<Omit<MutationHeaders, "Idempotency-Key">> {
    const Headers = await this.#mutationHeaders();
    return {
      Origin: Headers.Origin,
      "Sec-Fetch-Site": Headers["Sec-Fetch-Site"],
      "X-FileBelt-Csrf": Headers["X-FileBelt-Csrf"],
    };
  }
}

function RegistrationView(Value: RegistrationResponse): McpRegistrationView {
  return {
    AuthenticationState: Value.authentication_state,
    CapabilityState: Value.capability_state,
    CredentialKind: Value.credential_kind,
    CredentialPresent: Value.credential_present,
    DisplayName: Value.display_name,
    EndpointUri: Value.endpoint_uri,
    Etag: Value.etag,
    Id: Value.id,
    LifecycleState: Value.lifecycle_state,
    ManagedLocked: Value.managed_locked,
    Ownership: Value.ownership,
    QuarantineState: Value.quarantine_state,
    Transport: Value.transport,
    TrustProfile: Value.trust_profile,
    ValidationState: Value.validation_state,
  };
}

function CapabilityReviewView(Value: CapabilityReviewResponse): McpCapabilityReviewView {
  return {
    Capabilities: Value.snapshot.capabilities.map((Capability) => ({
      Description: Capability.description,
      Fingerprint: Capability.fingerprint,
      Kind: Capability.kind,
      Name: Capability.name,
      ReadOnlyHint: Capability.read_only_hint,
      Risk: Capability.risk,
      State: Capability.state,
      Title: Capability.title,
    })),
    Decisions: Object.fromEntries(
      Value.decisions.map((Decision) => [Decision.capability_fingerprint, Decision.decision]),
    ),
    SnapshotFingerprint: Value.snapshot.fingerprint,
    SnapshotId: Value.snapshot.id,
  };
}

function ActivityView(Value: components["schemas"]["McpActivity"]): McpActivityView {
  return {
    ApplicationId: Value.application_id,
    CapabilityFingerprint: Value.capability_fingerprint,
    CreatedAt: Value.created_at,
    DurationMs: Value.duration_ms,
    Id: Value.id,
    Outcome: Value.outcome,
    ReasonCode: Value.reason_code,
    RegistrationId: Value.registration_id,
  };
}

function TemplateView(Value: components["schemas"]["AdminMcpTemplate"]): AdminMcpTemplateView {
  return {
    AssignmentCount: Value.assignment_count,
    DisplayName: Value.display_name,
    Enabled: Value.enabled,
    EndpointUri: Value.endpoint_uri,
    Etag: Value.etag,
    Id: Value.id,
    Transport: Value.transport,
    TrustProfile: Value.trust_profile,
  };
}

function ServiceView(
  Value: components["schemas"]["AdminMcpServiceIdentity"],
): AdminMcpServiceIdentityView {
  return {
    DisplayName: Value.display_name,
    Etag: Value.etag,
    Id: Value.id,
    SpiffeUri: Value.spiffe_uri,
    State: Value.state,
  };
}

function BlockRuleView(Value: AdminBlockRuleResponse): AdminMcpBlockRuleView {
  return { Id: Value.id, Kind: Value.kind, Reason: Value.reason, Value: Value.value };
}

function InvocationRequest(Input: McpInvocationInput): InvocationRequest {
  return {
    application_id: Input.ApplicationId,
    arguments: Input.Arguments,
    attachments: [],
    capability: {
      fingerprint: Input.Capability.Fingerprint,
      kind: Input.Capability.Kind,
      name: Input.Capability.Name,
    },
    registration_id: Input.RegistrationId,
    ...(Input.SemanticInput === undefined
      ? {}
      : {
          semantic_input: {
            base_version_id: Input.SemanticInput.BaseVersionId,
            format: "filebelt.markdown.semantic.v1",
            markdown: Input.SemanticInput.Markdown,
            node_id: Input.SemanticInput.NodeId,
          },
        }),
  };
}

function RegistrationExport(Value: unknown): components["schemas"]["McpRegistrationExport"] {
  if (
    typeof Value !== "object" ||
    Value === null ||
    !("format" in Value) ||
    Value.format !== "filebelt.mcp-registration.v1"
  ) {
    throw new Error("The MCP registration JSON is invalid.");
  }
  return Value as components["schemas"]["McpRegistrationExport"];
}

function InvocationEventView(Value: InvocationEvent): McpInvocationEventView {
  if (
    Value.semantic_output?.format === "filebelt.markdown.semantic.v1" &&
    typeof Value.semantic_output.markdown === "string"
  )
    return {
      InvocationId: Value.invocation_id,
      Kind: "semanticMarkdown",
      Value: { Markdown: Value.semantic_output.markdown },
    };
  if (Value.event === "text" && typeof Value.text === "string")
    return { Kind: "text", Value: Value.text };
  if (Value.event === "json") return { Kind: "json", Value: Value.json };
  if (Value.event === "media" && Value.media !== null && Value.media !== undefined)
    return {
      Kind: "media",
      Value: {
        Base64: Value.media.base64,
        MimeType: Value.media.mime_type,
        SizeBytes: Value.media.size_bytes,
      },
    };
  if (Value.event === "error")
    return { Kind: "error", ProblemCode: Value.problem_code ?? "mcp.unknown" };
  if (Value.event === "progress")
    return Value.progress === null || Value.progress === undefined
      ? { Kind: "progress" }
      : { Kind: "progress", Progress: Value.progress };
  if (Value.event === "started" || Value.event === "completed") return { Kind: Value.event };
  return { Kind: "error", ProblemCode: "mcp.result_invalid" };
}

function DefaultBaseUrl(): string {
  return typeof window === "undefined" ? "https://filebelt.localhost" : window.location.origin;
}

function RequireData<T>(Result: ApiResult<unknown>): T {
  if (Result.response.ok && Result.data !== undefined) return Result.data as T;
  throw new Error(`FileBelt MCP request failed (${Result.response.status}).`);
}

function RequireSuccess(Result: ApiResult<unknown>): void {
  if (!Result.response.ok)
    throw new Error(`FileBelt MCP request failed (${Result.response.status}).`);
}

async function RequestError(Response: Response): Promise<Error> {
  if (Response.status === 401) return new AuthenticationRequiredError();
  try {
    const Problem: unknown = await Response.json();
    const Title = ProblemTitle(Problem);
    if (Title !== null) return new Error(Title);
  } catch {
    // Upstream response bodies are deliberately not exposed to the browser.
  }
  return new Error(`FileBelt MCP request failed (${Response.status}).`);
}

function ProblemTitle(Value: unknown): string | null {
  if (typeof Value !== "object" || Value === null || !("title" in Value)) return null;
  return typeof Value.title === "string" ? Value.title : null;
}
