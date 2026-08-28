// SPDX-License-Identifier: Apache-2.0

import type { SafeMediaValue } from './result-renderers.js'

export type McpTransport = 'stdio_catalog' | 'streamable_http'
export type McpRegistrationState = 'deleted' | 'disabled' | 'enabled' | 'revoking'
export type McpCapabilityKind = 'prompt' | 'resource' | 'tool'

export interface McpAttachmentPolicyView {
  AllowedEncodings: readonly ('base64' | 'utf8')[]
  AllowedMimePatterns: readonly string[]
  MaxAttachments: number
  MaxItemBytes: number
  MaxTotalBytes: number
}

export interface McpRegistrationView {
  AuthenticationState: 'expired' | 'missing' | 'not_required' | 'pending' | 'ready' | 'revoked'
  CapabilityState: 'changed' | 'review_required' | 'reviewed' | 'undiscovered'
  CredentialKind: 'api_key' | 'bearer' | 'none' | 'oauth'
  CredentialPresent: boolean
  DisplayName: string
  EndpointUri: string | null
  Etag: string
  Id: string
  LifecycleState: McpRegistrationState
  ManagedLocked: boolean
  Ownership: 'managed_group' | 'managed_service' | 'managed_user' | 'personal'
  QuarantineState: 'blocked' | 'clear' | 'quarantined'
  Transport: McpTransport
  TrustProfile: string
  ValidationState: 'invalid' | 'stale' | 'untested' | 'valid'
}

export interface CreateMcpRegistrationInput {
  DisplayName: string
  EndpointUri: string
  TrustProfile: string
}

export interface McpCapabilityView {
  Description: string | null
  Fingerprint: string
  Kind: McpCapabilityKind
  Name: string
  ReadOnlyHint: boolean | null
  Risk: 'elevated' | 'low' | 'prohibited'
  State: 'changed' | 'new' | 'removed' | 'unchanged'
  Title: string | null
}

export interface McpCapabilityReviewView {
  Capabilities: readonly McpCapabilityView[]
  Decisions: Readonly<Record<string, 'approved' | 'blocked'>>
  SnapshotFingerprint: string
  SnapshotId: string
}

export interface McpActivityView {
  ApplicationId: string
  CapabilityFingerprint: string
  CreatedAt: string
  DurationMs: number
  Id: string
  Outcome: 'cancelled' | 'denied' | 'failed' | 'interrupted' | 'succeeded'
  ReasonCode: string | null
  RegistrationId: string
}

export interface McpInvocationInput {
  ApplicationId: string
  Arguments: unknown
  Capability: {
    Fingerprint: string
    Kind: McpCapabilityKind
    Name: string
  }
  RegistrationId: string
  SemanticInput?: McpSemanticInput
}

export interface McpSemanticInput {
  BaseVersionId: string
  Markdown: string
  NodeId: string
}

export interface McpSemanticMarkdown {
  Markdown: string
}

export interface McpInvocationIntentView {
  ExpiresAt: string
  Id: string
  RequestDigest: string
}

export interface McpPreparedInvocation {
  Input: McpInvocationInput
  Intent: McpInvocationIntentView
}

export type McpInvocationEventView =
  | { Kind: 'completed' | 'progress' | 'started'; Progress?: number }
  | { Kind: 'error'; ProblemCode: string }
  | { Kind: 'json'; Value: unknown }
  | { Kind: 'media'; Value: SafeMediaValue }
  | { InvocationId: string; Kind: 'semanticMarkdown'; Value: McpSemanticMarkdown }
  | { Kind: 'text'; Value: string }

export interface AdminMcpTemplateView {
  AssignmentCount: number
  DisplayName: string
  Enabled: boolean
  EndpointUri: string | null
  Etag: string
  Id: string
  Transport: McpTransport
  TrustProfile: string
}

export interface AdminMcpServiceIdentityView {
  DisplayName: string
  Etag: string
  Id: string
  SpiffeUri: string
  State: 'active' | 'deleting' | 'suspended'
}

export interface AdminMcpBlockRuleView {
  Id: string
  Kind: 'capability' | 'catalog_entry' | 'origin' | 'registration' | 'trust_profile'
  Reason: string
  Value: string
}

export interface McpSettingsSnapshot {
  Activity: readonly McpActivityView[]
  BlockRules: readonly AdminMcpBlockRuleView[]
  Registrations: readonly McpRegistrationView[]
  ServiceIdentities: readonly AdminMcpServiceIdentityView[]
  Templates: readonly AdminMcpTemplateView[]
}

export interface McpSettingsClient {
  approveAndInvoke(
    // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The nested invocation DTO is caller-owned and observed without mutation.
    Prepared: Readonly<McpPreparedInvocation>,
    // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Union event payloads are observer values even though the mapped type is not deeply readonly.
    OnEvent: (Event: Readonly<McpInvocationEventView>) => void,
    Signal?: Readonly<AbortSignal>,
  ): Promise<void>
  assignTemplate(
    Template: Readonly<AdminMcpTemplateView>,
    PrincipalId: string,
    PrincipalKind: 'group' | 'service' | 'user',
  ): Promise<void>
  cancelInvocation(InvocationId: string): Promise<void>
  changeRegistrationState(
    Registration: Readonly<McpRegistrationView>,
    Action: 'disable' | 'enable' | 'revoke',
  ): Promise<void>
  createBlockRule(Kind: AdminMcpBlockRuleView['Kind'], Value: string, Reason: string): Promise<void>
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The nested invocation DTO is caller-owned and observed without mutation.
  createInvocationIntent(Input: Readonly<McpInvocationInput>): Promise<McpPreparedInvocation>
  createRegistration(Input: Readonly<CreateMcpRegistrationInput>): Promise<void>
  createServiceIdentity(DisplayName: string, SpiffeUri: string): Promise<void>
  createServiceInvocationGrant(
    Service: Readonly<AdminMcpServiceIdentityView>,
    RegistrationId: string,
    CapabilityKind: McpCapabilityKind,
    CapabilityName: string,
    CapabilityFingerprint: string,
    ApplicationId: string,
    ExpiresAt: string,
  ): Promise<void>
  createTemplate(DisplayName: string, EndpointUri: string, TrustProfile: string): Promise<void>
  deleteRegistration(Registration: Readonly<McpRegistrationView>): Promise<void>
  discoverCapabilities(
    Registration: Readonly<McpRegistrationView>,
  ): Promise<McpCapabilityReviewView>
  exportRegistration(RegistrationId: string): Promise<string>
  getCapabilityReview(RegistrationId: string): Promise<McpCapabilityReviewView | null>
  getSnapshot(IsTenantAdmin: boolean, Signal?: Readonly<AbortSignal>): Promise<McpSettingsSnapshot>
  importRegistration(Document: string): Promise<void>
  putCapabilityReview(
    Registration: Readonly<McpRegistrationView>,
    // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- Capability entries are caller-owned review values and are not mutated by clients.
    Review: Readonly<McpCapabilityReviewView>,
  ): Promise<void>
  putCredential(
    Registration: Readonly<McpRegistrationView>,
    Kind: 'api_key' | 'bearer',
    Secret: string,
  ): Promise<void>
  startOauth(Registration: Readonly<McpRegistrationView>): Promise<string>
  testRegistration(Registration: Readonly<McpRegistrationView>): Promise<boolean>
}
