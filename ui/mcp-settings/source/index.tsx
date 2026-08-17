// SPDX-License-Identifier: Apache-2.0

import {
  Badge,
  Button,
  Field,
  Input,
  Spinner,
  Tab as FluentTab,
  TabList,
  Textarea,
} from "@fluentui/react-components";
import {
  Activity,
  Ban,
  KeyRound,
  Plus,
  RefreshCw,
  ServerCog,
  ShieldCheck,
  TestTube2,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import type { FormEvent, ReactNode } from "react";

import type {
  AdminMcpBlockRuleView,
  McpCapabilityReviewView,
  McpInvocationEventView,
  McpPreparedInvocation,
  McpRegistrationView,
  McpSettingsClient,
  McpSettingsSnapshot,
} from "./model.js";
import { SafeJsonResult, SafeMediaResult, SafeTextResult } from "./result-renderers.js";
import { McpEn } from "./strings.js";

export type {
  AdminMcpBlockRuleView,
  AdminMcpServiceIdentityView,
  AdminMcpTemplateView,
  CreateMcpRegistrationInput,
  McpActivityView,
  McpAttachmentPolicyView,
  McpCapabilityReviewView,
  McpCapabilityView,
  McpInvocationEventView,
  McpInvocationInput,
  McpInvocationIntentView,
  McpPreparedInvocation,
  McpRegistrationView,
  McpSettingsClient,
  McpSettingsSnapshot,
} from "./model.js";
export { SafeJsonResult, SafeMediaResult, SafeTextResult } from "./result-renderers.js";

interface McpSettingsProps {
  Client: McpSettingsClient;
  IsTenantAdmin: boolean;
}

type SettingsTab = "activity" | "admin" | "servers";

const EmptySnapshot: McpSettingsSnapshot = {
  Activity: [],
  BlockRules: [],
  Registrations: [],
  ServiceIdentities: [],
  Templates: [],
};

function Bidi({ Value }: { Value: string }): ReactNode {
  return <bdi dir="auto">{Value}</bdi>;
}

function RegistrationStatus({ Registration }: { Registration: McpRegistrationView }): ReactNode {
  const Unsafe =
    Registration.QuarantineState !== "clear" || Registration.ValidationState === "invalid";
  const Color = Unsafe
    ? "danger"
    : Registration.LifecycleState === "enabled"
      ? "success"
      : "informative";
  return (
    <Badge appearance="tint" color={Color}>
      {Registration.LifecycleState}
    </Badge>
  );
}

function DownloadConfiguration(Document: string, Registration: McpRegistrationView): void {
  const Url = URL.createObjectURL(new Blob([Document], { type: "application/json" }));
  const Anchor = document.createElement("a");
  Anchor.download = `${Registration.DisplayName.replaceAll(/[^A-Za-z0-9._-]+/g, "-") || "mcp-registration"}.json`;
  Anchor.href = Url;
  Anchor.click();
  URL.revokeObjectURL(Url);
}

function InvocationResult({ Event }: { Event: McpInvocationEventView }): ReactNode {
  if (Event.Kind === "text") return <SafeTextResult Value={Event.Value} />;
  if (Event.Kind === "json") return <SafeJsonResult Value={Event.Value} />;
  if (Event.Kind === "media") return <SafeMediaResult Value={Event.Value} />;
  if (Event.Kind === "semanticMarkdown")
    return (
      <pre className="fb-mcp-text">
        <bdi>{Event.Value.Markdown}</bdi>
      </pre>
    );
  if (Event.Kind === "error")
    return (
      <p className="fb-error" role="alert">
        <Bidi Value={Event.ProblemCode} />
      </p>
    );
  if (Event.Kind === "progress")
    return <progress aria-label={McpEn.invocationProgress} max={1} value={Event.Progress ?? 0} />;
  return <p className="fb-muted">{Event.Kind}</p>;
}

function AddRegistrationForm({
  Busy,
  onCreate: OnCreate,
  onImport: OnImport,
}: {
  Busy: boolean;
  onCreate(DisplayName: string, EndpointUri: string, TrustProfile: string): Promise<void>;
  onImport(Document: string): Promise<void>;
}): ReactNode {
  const [DisplayName, SetDisplayName] = useState("");
  const [EndpointUri, SetEndpointUri] = useState("");
  const [TrustProfile, SetTrustProfile] = useState("public-webpki");
  const [ImportDocument, SetImportDocument] = useState("");
  const Submit = async (Event: FormEvent): Promise<void> => {
    Event.preventDefault();
    if (DisplayName.trim().length === 0 || EndpointUri.trim().length === 0) return;
    await OnCreate(DisplayName.trim(), EndpointUri.trim(), TrustProfile.trim());
    SetDisplayName("");
    SetEndpointUri("");
  };
  const Import = async (): Promise<void> => {
    if (ImportDocument.trim().length === 0) return;
    await OnImport(ImportDocument);
    SetImportDocument("");
  };
  return (
    <form className="fb-mcp-form" onSubmit={(Event) => void Submit(Event)}>
      <Field label={McpEn.name} required>
        <Input
          disabled={Busy}
          maxLength={120}
          onChange={(Ignored, Data) => SetDisplayName(Data.value)}
          value={DisplayName}
        />
      </Field>
      <Field hint={McpEn.endpointHint} label={McpEn.endpoint} required>
        <Input
          disabled={Busy}
          maxLength={2048}
          onChange={(Ignored, Data) => SetEndpointUri(Data.value)}
          type="url"
          value={EndpointUri}
        />
      </Field>
      <Field label={McpEn.trustProfile} required>
        <Input
          disabled={Busy}
          maxLength={64}
          onChange={(Ignored, Data) => SetTrustProfile(Data.value)}
          value={TrustProfile}
        />
      </Field>
      <Button
        appearance="primary"
        disabled={Busy || DisplayName.trim().length === 0 || EndpointUri.trim().length === 0}
        icon={<Plus aria-hidden="true" />}
        type="submit"
      >
        {McpEn.add}
      </Button>
      <details>
        <summary>{McpEn.import}</summary>
        <Field label={McpEn.importDocument}>
          <Textarea
            disabled={Busy}
            onChange={(Ignored, Data) => SetImportDocument(Data.value)}
            resize="vertical"
            value={ImportDocument}
          />
        </Field>
        <Button
          disabled={Busy || ImportDocument.trim().length === 0}
          onClick={() => void Import()}
          type="button"
        >
          {McpEn.import}
        </Button>
      </details>
    </form>
  );
}

function CredentialForm({
  Busy,
  Registration,
  onOauth: OnOauth,
  onSave: OnSave,
}: {
  Busy: boolean;
  Registration: McpRegistrationView;
  onOauth(): Promise<void>;
  onSave(Kind: "api_key" | "bearer", Secret: string): Promise<void>;
}): ReactNode {
  const [Kind, SetKind] = useState<"api_key" | "bearer">("bearer");
  const [Secret, SetSecret] = useState("");
  const Submit = async (Event: FormEvent): Promise<void> => {
    Event.preventDefault();
    if (Secret.length === 0) return;
    await OnSave(Kind, Secret);
    SetSecret("");
  };
  return (
    <section aria-labelledby="mcp-auth-heading" className="fb-mcp-section">
      <h3 id="mcp-auth-heading">
        <KeyRound aria-hidden="true" size={18} /> {McpEn.authentication}
      </h3>
      <p className="fb-muted">{McpEn.credentialNotice}</p>
      <form className="fb-mcp-inline-form" onSubmit={(Event) => void Submit(Event)}>
        <Field label={McpEn.credentialType}>
          <select
            disabled={Busy}
            onChange={(Event) => SetKind(Event.currentTarget.value as "api_key" | "bearer")}
            value={Kind}
          >
            <option value="bearer">{McpEn.bearer}</option>
            <option value="api_key">{McpEn.apiKey}</option>
          </select>
        </Field>
        <Field label={McpEn.secret} required>
          <Input
            autoComplete="new-password"
            disabled={Busy}
            maxLength={8192}
            onChange={(Ignored, Data) => SetSecret(Data.value)}
            type="password"
            value={Secret}
          />
        </Field>
        <Button disabled={Busy || Secret.length === 0} type="submit">
          {McpEn.saveCredential}
        </Button>
        <Button appearance="secondary" disabled={Busy} onClick={() => void OnOauth()} type="button">
          {McpEn.connectOauth}
        </Button>
      </form>
      <p className="fb-muted">{McpEn.oauthNotice}</p>
      <p className="fb-muted">
        {McpEn.credentialState}: <Bidi Value={Registration.AuthenticationState} />
      </p>
    </section>
  );
}

function CapabilityReview({
  Busy,
  Registration,
  Review,
  onDiscover: OnDiscover,
  onSave: OnSave,
}: {
  Busy: boolean;
  Registration: McpRegistrationView;
  Review: McpCapabilityReviewView | null;
  onDiscover(): Promise<void>;
  onSave(Review: McpCapabilityReviewView): Promise<void>;
}): ReactNode {
  const [Decisions, SetDecisions] = useState<Readonly<Record<string, "approved" | "blocked">>>({});
  useEffect(() => SetDecisions(Review?.Decisions ?? {}), [Review]);
  const UpdatedReview = Review === null ? null : { ...Review, Decisions };
  return (
    <section aria-labelledby="mcp-capabilities-heading" className="fb-mcp-section">
      <div className="fb-mcp-section-heading">
        <h3 id="mcp-capabilities-heading">
          <ShieldCheck aria-hidden="true" size={18} /> {McpEn.capabilities}
        </h3>
        <Button
          disabled={Busy}
          icon={<RefreshCw aria-hidden="true" />}
          onClick={() => void OnDiscover()}
        >
          {McpEn.discover}
        </Button>
      </div>
      {Registration.CapabilityState === "changed" ? (
        <p className="fb-error" role="alert">
          {McpEn.capabilityChanged}
        </p>
      ) : null}
      {Review === null || Review.Capabilities.length === 0 ? (
        <p className="fb-muted">{McpEn.noCapabilities}</p>
      ) : (
        <div className="fb-mcp-capabilities" role="list">
          {Review.Capabilities.map((Capability) => {
            const Decision = Decisions[Capability.Fingerprint];
            const CanApprove =
              Capability.Risk !== "prohibited" &&
              (Capability.Kind !== "tool" || Capability.ReadOnlyHint === true);
            return (
              <article className="fb-mcp-capability" key={Capability.Fingerprint} role="listitem">
                <div className="fb-grow">
                  <strong>
                    <Bidi Value={Capability.Title ?? Capability.Name} />
                  </strong>
                  <span className="fb-muted">
                    <Bidi Value={Capability.Description ?? Capability.Name} />
                  </span>
                  <small>
                    {Capability.Kind} · {Capability.Risk} · read-only hint{" "}
                    {String(Capability.ReadOnlyHint)}
                  </small>
                </div>
                <div className="fb-heading-actions">
                  <Button
                    appearance={Decision === "approved" ? "primary" : "secondary"}
                    disabled={!CanApprove || Busy}
                    onClick={() =>
                      SetDecisions({ ...Decisions, [Capability.Fingerprint]: "approved" })
                    }
                  >
                    {McpEn.approve}
                  </Button>
                  <Button
                    appearance={Decision === "blocked" ? "primary" : "secondary"}
                    disabled={Busy}
                    onClick={() =>
                      SetDecisions({ ...Decisions, [Capability.Fingerprint]: "blocked" })
                    }
                  >
                    {McpEn.block}
                  </Button>
                </div>
              </article>
            );
          })}
        </div>
      )}
      <Button
        disabled={
          Busy ||
          UpdatedReview === null ||
          UpdatedReview.Capabilities.some(({ Fingerprint }) => Decisions[Fingerprint] === undefined)
        }
        onClick={() => (UpdatedReview === null ? undefined : void OnSave(UpdatedReview))}
      >
        {McpEn.review}
      </Button>
    </section>
  );
}

function InvocationForm({
  Busy,
  Registration,
  Review,
  onPrepare: OnPrepare,
}: {
  Busy: boolean;
  Registration: McpRegistrationView;
  Review: McpCapabilityReviewView | null;
  onPrepare(Fingerprint: string, Arguments: unknown): Promise<void>;
}): ReactNode {
  const Approved =
    Review?.Capabilities.filter(
      ({ Fingerprint }) => Review.Decisions[Fingerprint] === "approved",
    ) ?? [];
  const [Fingerprint, SetFingerprint] = useState("");
  const [ArgumentsText, SetArgumentsText] = useState("{}");
  const [ParseError, SetParseError] = useState<string | null>(null);
  useEffect(
    () => SetFingerprint(Approved[0]?.Fingerprint ?? ""),
    [Registration.Id, Review?.SnapshotId],
  );
  const Submit = async (Event: FormEvent): Promise<void> => {
    Event.preventDefault();
    try {
      const Arguments = JSON.parse(ArgumentsText) as unknown;
      SetParseError(null);
      await OnPrepare(Fingerprint, Arguments);
    } catch (Cause) {
      SetParseError(Cause instanceof SyntaxError ? McpEn.argumentsInvalid : McpEn.error);
    }
  };
  return (
    <section aria-labelledby="mcp-invoke-heading" className="fb-mcp-section">
      <h3 id="mcp-invoke-heading">
        <TestTube2 aria-hidden="true" size={18} /> {McpEn.invoke}
      </h3>
      <form className="fb-mcp-form" onSubmit={(Event) => void Submit(Event)}>
        <Field label={McpEn.approvedCapability}>
          <select
            disabled={Busy || Approved.length === 0}
            onChange={(Event) => SetFingerprint(Event.currentTarget.value)}
            value={Fingerprint}
          >
            {Approved.map((Capability) => (
              <option key={Capability.Fingerprint} value={Capability.Fingerprint}>
                {McpEn.capabilityOption(
                  Capability.Title ?? Capability.Name,
                  Capability.Kind,
                  Capability.Name,
                )}
              </option>
            ))}
          </select>
        </Field>
        <Field
          {...(ParseError === null
            ? {}
            : { validationMessage: ParseError, validationState: "error" as const })}
          label={McpEn.jsonArguments}
        >
          <Textarea
            disabled={Busy}
            onChange={(Ignored, Data) => SetArgumentsText(Data.value)}
            resize="vertical"
            value={ArgumentsText}
          />
        </Field>
        <Button
          appearance="primary"
          disabled={Busy || Registration.LifecycleState !== "enabled" || Fingerprint.length === 0}
          type="submit"
        >
          {McpEn.invoke}
        </Button>
      </form>
    </section>
  );
}

function AdminSurface({
  Busy,
  Snapshot,
  onAssign: OnAssign,
  onBlock: OnBlock,
  onService: OnService,
  onServiceGrant: OnServiceGrant,
  onTemplate: OnTemplate,
}: {
  Busy: boolean;
  Snapshot: McpSettingsSnapshot;
  onAssign(
    TemplateId: string,
    PrincipalId: string,
    PrincipalKind: "group" | "service" | "user",
  ): Promise<void>;
  onBlock(Kind: AdminMcpBlockRuleView["Kind"], Value: string, Reason: string): Promise<void>;
  onService(Name: string, SpiffeUri: string): Promise<void>;
  onServiceGrant(
    ServiceId: string,
    RegistrationId: string,
    CapabilityKind: "prompt" | "resource" | "tool",
    CapabilityName: string,
    CapabilityFingerprint: string,
    ApplicationId: string,
    ExpiresAt: string,
  ): Promise<void>;
  onTemplate(Name: string, Endpoint: string, Profile: string): Promise<void>;
}): ReactNode {
  const [TemplateName, SetTemplateName] = useState("");
  const [TemplateEndpoint, SetTemplateEndpoint] = useState("");
  const [ServiceName, SetServiceName] = useState("");
  const [SpiffeUri, SetSpiffeUri] = useState("");
  const [BlockValue, SetBlockValue] = useState("");
  const [AssignmentTemplateId, SetAssignmentTemplateId] = useState("");
  const [AssignmentPrincipalId, SetAssignmentPrincipalId] = useState("");
  const [AssignmentPrincipalKind, SetAssignmentPrincipalKind] = useState<
    "group" | "service" | "user"
  >("user");
  const [GrantServiceId, SetGrantServiceId] = useState("");
  const [GrantRegistrationId, SetGrantRegistrationId] = useState("");
  const [GrantCapabilityKind, SetGrantCapabilityKind] = useState<"prompt" | "resource" | "tool">(
    "tool",
  );
  const [GrantCapabilityName, SetGrantCapabilityName] = useState("");
  const [GrantFingerprint, SetGrantFingerprint] = useState("");
  const [GrantApplicationId, SetGrantApplicationId] = useState("");
  const SubmitTemplate = async (Event: FormEvent): Promise<void> => {
    Event.preventDefault();
    await OnTemplate(TemplateName, TemplateEndpoint, "public-webpki");
    SetTemplateName("");
    SetTemplateEndpoint("");
  };
  const SubmitService = async (Event: FormEvent): Promise<void> => {
    Event.preventDefault();
    await OnService(ServiceName, SpiffeUri);
    SetServiceName("");
    SetSpiffeUri("");
  };
  const SubmitBlock = async (Event: FormEvent): Promise<void> => {
    Event.preventDefault();
    await OnBlock("origin", BlockValue, "Blocked by tenant administrator");
    SetBlockValue("");
  };
  const SubmitAssignment = async (Event: FormEvent): Promise<void> => {
    Event.preventDefault();
    await OnAssign(AssignmentTemplateId, AssignmentPrincipalId, AssignmentPrincipalKind);
    SetAssignmentPrincipalId("");
  };
  const SubmitGrant = async (Event: FormEvent): Promise<void> => {
    Event.preventDefault();
    const ExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    await OnServiceGrant(
      GrantServiceId,
      GrantRegistrationId,
      GrantCapabilityKind,
      GrantCapabilityName,
      GrantFingerprint,
      GrantApplicationId,
      ExpiresAt,
    );
    SetGrantCapabilityName("");
    SetGrantFingerprint("");
    SetGrantApplicationId("");
  };
  return (
    <section aria-labelledby="mcp-admin-heading" className="fb-mcp-admin">
      <h2 id="mcp-admin-heading">{McpEn.administration}</h2>
      <p className="fb-muted">{McpEn.adminNotice}</p>
      <div className="fb-mcp-admin-grid">
        <form className="fb-mcp-section" onSubmit={(Event) => void SubmitTemplate(Event)}>
          <h3>{McpEn.managedTemplates}</h3>
          <Field label={McpEn.name}>
            <Input
              disabled={Busy}
              onChange={(Ignored, Data) => SetTemplateName(Data.value)}
              value={TemplateName}
            />
          </Field>
          <Field label={McpEn.endpoint}>
            <Input
              disabled={Busy}
              onChange={(Ignored, Data) => SetTemplateEndpoint(Data.value)}
              type="url"
              value={TemplateEndpoint}
            />
          </Field>
          <Button
            disabled={Busy || TemplateName.length === 0 || TemplateEndpoint.length === 0}
            type="submit"
          >
            {McpEn.createTemplate}
          </Button>
          <ul>
            {Snapshot.Templates.map((Template) => (
              <li key={Template.Id}>
                <Bidi Value={Template.DisplayName} /> ·{" "}
                {McpEn.assignmentCount(Template.AssignmentCount)}
              </li>
            ))}
          </ul>
        </form>
        <form className="fb-mcp-section" onSubmit={(Event) => void SubmitAssignment(Event)}>
          <h3>{McpEn.templateAssignments}</h3>
          <Field label={McpEn.managedTemplate}>
            <select
              disabled={Busy}
              onChange={(Event) => SetAssignmentTemplateId(Event.currentTarget.value)}
              value={AssignmentTemplateId}
            >
              <option value="">{McpEn.selectTemplate}</option>
              {Snapshot.Templates.map((Template) => (
                <option key={Template.Id} value={Template.Id}>
                  {Template.DisplayName}
                </option>
              ))}
            </select>
          </Field>
          <Field label={McpEn.principalKind}>
            <select
              disabled={Busy}
              onChange={(Event) =>
                SetAssignmentPrincipalKind(
                  Event.currentTarget.value as "group" | "service" | "user",
                )
              }
              value={AssignmentPrincipalKind}
            >
              <option value="user">{McpEn.user}</option>
              <option value="group">{McpEn.group}</option>
              <option value="service">{McpEn.service}</option>
            </select>
          </Field>
          <Field label={McpEn.exactPrincipalId}>
            <Input
              disabled={Busy}
              onChange={(Ignored, Data) => SetAssignmentPrincipalId(Data.value)}
              value={AssignmentPrincipalId}
            />
          </Field>
          <Button
            disabled={
              Busy || AssignmentTemplateId.length === 0 || AssignmentPrincipalId.length === 0
            }
            type="submit"
          >
            {McpEn.assignTemplate}
          </Button>
        </form>
        <form className="fb-mcp-section" onSubmit={(Event) => void SubmitService(Event)}>
          <h3>{McpEn.serviceIdentities}</h3>
          <Field label={McpEn.displayName}>
            <Input
              disabled={Busy}
              onChange={(Ignored, Data) => SetServiceName(Data.value)}
              value={ServiceName}
            />
          </Field>
          <Field label={McpEn.exactSpiffeUri}>
            <Input
              disabled={Busy}
              onChange={(Ignored, Data) => SetSpiffeUri(Data.value)}
              type="url"
              value={SpiffeUri}
            />
          </Field>
          <Button
            disabled={Busy || ServiceName.length === 0 || !SpiffeUri.startsWith("spiffe://")}
            type="submit"
          >
            {McpEn.createService}
          </Button>
          <ul>
            {Snapshot.ServiceIdentities.map((Service) => (
              <li key={Service.Id}>
                <Bidi Value={Service.DisplayName} /> · <Bidi Value={Service.State} />
              </li>
            ))}
          </ul>
        </form>
        <form className="fb-mcp-section" onSubmit={(Event) => void SubmitGrant(Event)}>
          <h3>{McpEn.serviceGrants}</h3>
          <p className="fb-muted">{McpEn.serviceGrantNotice}</p>
          <Field label={McpEn.service}>
            <select
              disabled={Busy}
              onChange={(Event) => SetGrantServiceId(Event.currentTarget.value)}
              value={GrantServiceId}
            >
              <option value="">{McpEn.selectService}</option>
              {Snapshot.ServiceIdentities.map((Service) => (
                <option key={Service.Id} value={Service.Id}>
                  {Service.DisplayName}
                </option>
              ))}
            </select>
          </Field>
          <Field label={McpEn.registration}>
            <select
              disabled={Busy}
              onChange={(Event) => SetGrantRegistrationId(Event.currentTarget.value)}
              value={GrantRegistrationId}
            >
              <option value="">{McpEn.selectRegistration}</option>
              {Snapshot.Registrations.map((Registration) => (
                <option key={Registration.Id} value={Registration.Id}>
                  {Registration.DisplayName}
                </option>
              ))}
            </select>
          </Field>
          <Field label={McpEn.capabilityKind}>
            <select
              disabled={Busy}
              onChange={(Event) =>
                SetGrantCapabilityKind(Event.currentTarget.value as "prompt" | "resource" | "tool")
              }
              value={GrantCapabilityKind}
            >
              <option value="resource">{McpEn.resource}</option>
              <option value="prompt">{McpEn.prompt}</option>
              <option value="tool">{McpEn.tool}</option>
            </select>
          </Field>
          <Field label={McpEn.capabilityName}>
            <Input
              disabled={Busy}
              maxLength={256}
              onChange={(Ignored, Data) => SetGrantCapabilityName(Data.value)}
              value={GrantCapabilityName}
            />
          </Field>
          <Field label={McpEn.capabilityFingerprint}>
            <Input
              disabled={Busy}
              maxLength={64}
              onChange={(Ignored, Data) => SetGrantFingerprint(Data.value)}
              value={GrantFingerprint}
            />
          </Field>
          <Field label={McpEn.applicationId}>
            <Input
              disabled={Busy}
              maxLength={128}
              onChange={(Ignored, Data) => SetGrantApplicationId(Data.value)}
              value={GrantApplicationId}
            />
          </Field>
          <Button
            disabled={
              Busy ||
              GrantServiceId.length === 0 ||
              GrantRegistrationId.length === 0 ||
              GrantCapabilityName.length === 0 ||
              !/^[0-9a-f]{64}$/.test(GrantFingerprint) ||
              GrantApplicationId.length === 0
            }
            type="submit"
          >
            {McpEn.createGrant}
          </Button>
        </form>
        <form className="fb-mcp-section" onSubmit={(Event) => void SubmitBlock(Event)}>
          <h3>
            <Ban aria-hidden="true" size={18} /> {McpEn.originBlocks}
          </h3>
          <Field label={McpEn.exactOrigin}>
            <Input
              disabled={Busy}
              onChange={(Ignored, Data) => SetBlockValue(Data.value)}
              type="url"
              value={BlockValue}
            />
          </Field>
          <Button disabled={Busy || BlockValue.length === 0} type="submit">
            {McpEn.blockOrigin}
          </Button>
          <ul>
            {Snapshot.BlockRules.map((Rule) => (
              <li key={Rule.Id}>
                <Bidi Value={Rule.Value} /> · <Bidi Value={Rule.Reason} />
              </li>
            ))}
          </ul>
        </form>
      </div>
    </section>
  );
}

export default function McpSettings({ Client, IsTenantAdmin }: McpSettingsProps): ReactNode {
  const [Tab, SetTab] = useState<SettingsTab>("servers");
  const [Snapshot, SetSnapshot] = useState<McpSettingsSnapshot>(EmptySnapshot);
  const [SelectedId, SetSelectedId] = useState<string | null>(null);
  const [Review, SetReview] = useState<McpCapabilityReviewView | null>(null);
  const [Events, SetEvents] = useState<readonly McpInvocationEventView[]>([]);
  const [PendingInvocation, SetPendingInvocation] = useState<McpPreparedInvocation | null>(null);
  const [ActiveInvocationId, SetActiveInvocationId] = useState<string | null>(null);
  const [Busy, SetBusy] = useState(false);
  const [Loading, SetLoading] = useState(true);
  const [ErrorMessage, SetError] = useState<string | null>(null);
  const Selected =
    Snapshot.Registrations.find(({ Id }) => Id === SelectedId) ?? Snapshot.Registrations[0] ?? null;

  const Refresh = useCallback(
    async (Signal?: AbortSignal): Promise<void> => {
      try {
        const Next = await Client.getSnapshot(IsTenantAdmin, Signal);
        SetSnapshot(Next);
        SetSelectedId((Current) => Current ?? Next.Registrations[0]?.Id ?? null);
        SetError(null);
      } catch (Cause) {
        if (!(Cause instanceof DOMException && Cause.name === "AbortError"))
          SetError(Cause instanceof Error ? Cause.message : McpEn.error);
      } finally {
        SetLoading(false);
      }
    },
    [Client, IsTenantAdmin],
  );

  useEffect(() => {
    const Controller = new AbortController();
    void Refresh(Controller.signal);
    return () => Controller.abort();
  }, [Refresh]);
  useEffect(() => {
    if (Selected === null) {
      SetReview(null);
      return;
    }
    let Active = true;
    void Client.getCapabilityReview(Selected.Id)
      .then((Value) => {
        if (Active) SetReview(Value);
      })
      .catch(() => {
        if (Active) SetReview(null);
      });
    return () => {
      Active = false;
    };
  }, [Client, Selected?.Id]);

  const Mutate = async (Operation: () => Promise<void>): Promise<void> => {
    SetBusy(true);
    SetError(null);
    try {
      await Operation();
      await Refresh();
    } catch (Cause) {
      SetError(Cause instanceof Error ? Cause.message : McpEn.error);
    } finally {
      SetBusy(false);
    }
  };
  const PrepareInvocation = async (Fingerprint: string, Arguments: unknown): Promise<void> => {
    if (Selected === null || Review === null) return;
    const Capability = Review.Capabilities.find((Item) => Item.Fingerprint === Fingerprint);
    if (Capability === undefined) return;
    SetEvents([]);
    SetBusy(true);
    try {
      SetPendingInvocation(
        await Client.createInvocationIntent({
          ApplicationId: "filebelt-web",
          Arguments,
          Capability: {
            Fingerprint: Capability.Fingerprint,
            Kind: Capability.Kind,
            Name: Capability.Name,
          },
          RegistrationId: Selected.Id,
        }),
      );
    } catch (Cause) {
      SetError(Cause instanceof Error ? Cause.message : McpEn.error);
    } finally {
      SetBusy(false);
    }
  };
  const Invoke = async (Prepared: McpPreparedInvocation): Promise<void> => {
    SetPendingInvocation(null);
    SetActiveInvocationId(Prepared.Intent.Id);
    SetBusy(true);
    SetError(null);
    try {
      await Client.approveAndInvoke(Prepared, (Event) =>
        SetEvents((Current) => [...Current, Event]),
      );
      await Refresh();
    } catch (Cause) {
      SetError(Cause instanceof Error ? Cause.message : McpEn.error);
    } finally {
      SetActiveInvocationId(null);
      SetBusy(false);
    }
  };

  return (
    <section aria-labelledby="mcp-heading" className="fb-mcp-page">
      <header className="fb-page-heading">
        <div>
          <p className="fb-eyebrow">
            <ServerCog aria-hidden="true" size={18} /> MCP
          </p>
          <h1 id="mcp-heading">{McpEn.registrationHeading}</h1>
          <p className="fb-muted">{McpEn.description}</p>
        </div>
        <Button
          disabled={Busy}
          icon={<RefreshCw aria-hidden="true" />}
          onClick={() => void Refresh()}
        >
          {McpEn.refresh}
        </Button>
      </header>
      {ErrorMessage === null ? null : (
        <p className="fb-error" role="alert">
          {ErrorMessage}
        </p>
      )}
      <TabList
        aria-label={McpEn.registrationHeading}
        onTabSelect={(Ignored, Data) => SetTab(Data.value as SettingsTab)}
        selectedValue={Tab}
      >
        <FluentTab icon={<ServerCog aria-hidden="true" />} value="servers">
          {McpEn.registrationHeading}
        </FluentTab>
        <FluentTab icon={<Activity aria-hidden="true" />} value="activity">
          {McpEn.activity}
        </FluentTab>
        {IsTenantAdmin ? (
          <FluentTab icon={<ShieldCheck aria-hidden="true" />} value="admin">
            {McpEn.administration}
          </FluentTab>
        ) : null}
      </TabList>
      {Loading ? (
        <div className="fb-loading">
          <Spinner label={McpEn.working} />
        </div>
      ) : null}
      {!Loading && Tab === "servers" ? (
        <div className="fb-mcp-layout">
          <aside aria-label={McpEn.registrationList} className="fb-mcp-sidebar">
            <AddRegistrationForm
              Busy={Busy}
              onCreate={(DisplayName, EndpointUri, TrustProfile) =>
                Mutate(() => Client.createRegistration({ DisplayName, EndpointUri, TrustProfile }))
              }
              onImport={(Document) => Mutate(() => Client.importRegistration(Document))}
            />
            <div role="list">
              {Snapshot.Registrations.length === 0 ? (
                <p className="fb-muted">{McpEn.empty}</p>
              ) : (
                Snapshot.Registrations.map((Registration) => (
                  <button
                    aria-current={Selected?.Id === Registration.Id ? "true" : undefined}
                    className={
                      Selected?.Id === Registration.Id
                        ? "fb-mcp-registration is-selected"
                        : "fb-mcp-registration"
                    }
                    key={Registration.Id}
                    onClick={() => SetSelectedId(Registration.Id)}
                    role="listitem"
                    type="button"
                  >
                    <span>
                      <Bidi Value={Registration.DisplayName} />
                    </span>
                    <RegistrationStatus Registration={Registration} />
                    <small>
                      {Registration.Ownership === "personal" ? McpEn.personal : McpEn.managed}
                    </small>
                  </button>
                ))
              )}
            </div>
          </aside>
          {Selected === null ? (
            <div className="fb-empty">
              <p>{McpEn.empty}</p>
            </div>
          ) : (
            <div className="fb-mcp-detail">
              <header className="fb-mcp-detail-heading">
                <div>
                  <h2>
                    <Bidi Value={Selected.DisplayName} />
                  </h2>
                  <p className="fb-muted">
                    <Bidi Value={Selected.EndpointUri ?? Selected.Transport} />
                  </p>
                </div>
                <RegistrationStatus Registration={Selected} />
              </header>
              {Selected.ManagedLocked ? (
                <p className="fb-mcp-notice">{McpEn.managedLocked}</p>
              ) : null}
              <div className="fb-heading-actions">
                <Button
                  disabled={Busy}
                  icon={<TestTube2 aria-hidden="true" />}
                  onClick={() =>
                    void Mutate(async () => {
                      await Client.testRegistration(Selected);
                    })
                  }
                >
                  {McpEn.test}
                </Button>
                <Button
                  disabled={
                    Busy ||
                    Selected.ValidationState !== "valid" ||
                    Selected.CapabilityState !== "reviewed"
                  }
                  onClick={() =>
                    void Mutate(() =>
                      Client.changeRegistrationState(
                        Selected,
                        Selected.LifecycleState === "enabled" ? "disable" : "enable",
                      ),
                    )
                  }
                >
                  {Selected.LifecycleState === "enabled" ? McpEn.disable : McpEn.enable}
                </Button>
                <Button
                  appearance="secondary"
                  disabled={Busy}
                  onClick={() =>
                    void Mutate(() => Client.changeRegistrationState(Selected, "revoke"))
                  }
                >
                  {McpEn.revoke}
                </Button>
                <Button
                  appearance="secondary"
                  disabled={Busy}
                  onClick={() =>
                    void Client.exportRegistration(Selected.Id)
                      .then((Document) => DownloadConfiguration(Document, Selected))
                      .catch((Cause: unknown) =>
                        SetError(Cause instanceof Error ? Cause.message : McpEn.error),
                      )
                  }
                >
                  {McpEn.export}
                </Button>
                <Button
                  appearance="secondary"
                  disabled={Busy || Selected.ManagedLocked}
                  onClick={() => void Mutate(() => Client.deleteRegistration(Selected))}
                >
                  {McpEn.delete}
                </Button>
              </div>
              <CredentialForm
                Busy={Busy}
                key={Selected.Id}
                onOauth={async () => {
                  const Url = await Client.startOauth(Selected);
                  window.location.assign(Url);
                }}
                onSave={(Kind, Secret) =>
                  Mutate(() => Client.putCredential(Selected, Kind, Secret))
                }
                Registration={Selected}
              />
              <CapabilityReview
                Busy={Busy}
                onDiscover={async () => {
                  const Value = await Client.discoverCapabilities(Selected);
                  SetReview(Value);
                  await Refresh();
                }}
                onSave={(Value) =>
                  Mutate(async () => {
                    await Client.putCapabilityReview(Selected, Value);
                    SetReview(Value);
                  })
                }
                Registration={Selected}
                Review={Review}
              />
              <InvocationForm
                Busy={Busy}
                onPrepare={PrepareInvocation}
                Registration={Selected}
                Review={Review}
              />
              {PendingInvocation === null ? null : (
                <section
                  aria-labelledby="mcp-confirm-heading"
                  className="fb-mcp-section fb-mcp-confirm"
                >
                  <h3 id="mcp-confirm-heading">{McpEn.confirmInvocation}</h3>
                  <p>{McpEn.confirmInvocationNotice}</p>
                  <dl>
                    <div>
                      <dt>{McpEn.server}</dt>
                      <dd>
                        <Bidi
                          Value={
                            Snapshot.Registrations.find(
                              ({ Id }) => Id === PendingInvocation.Input.RegistrationId,
                            )?.DisplayName ?? PendingInvocation.Input.RegistrationId
                          }
                        />
                      </dd>
                    </div>
                    <div>
                      <dt>{McpEn.capabilityKind}</dt>
                      <dd>
                        <Bidi Value={PendingInvocation.Input.Capability.Kind} />
                      </dd>
                    </div>
                    <div>
                      <dt>{McpEn.capabilityName}</dt>
                      <dd>
                        <Bidi Value={PendingInvocation.Input.Capability.Name} />
                      </dd>
                    </div>
                    <div>
                      <dt>{McpEn.capabilityFingerprint}</dt>
                      <dd>
                        <Bidi Value={PendingInvocation.Input.Capability.Fingerprint} />
                      </dd>
                    </div>
                    <div>
                      <dt>{McpEn.application}</dt>
                      <dd>
                        <Bidi Value={PendingInvocation.Input.ApplicationId} />
                      </dd>
                    </div>
                    <div>
                      <dt>{McpEn.attachments}</dt>
                      <dd>{McpEn.none}</dd>
                    </div>
                    <div>
                      <dt>{McpEn.intentExpires}</dt>
                      <dd>{new Date(PendingInvocation.Intent.ExpiresAt).toLocaleString()}</dd>
                    </div>
                  </dl>
                  <SafeJsonResult Value={PendingInvocation.Input.Arguments} />
                  <div className="fb-heading-actions">
                    <Button
                      appearance="primary"
                      disabled={Busy}
                      onClick={() => void Invoke(PendingInvocation)}
                    >
                      {McpEn.approveOnce}
                    </Button>
                    <Button disabled={Busy} onClick={() => SetPendingInvocation(null)}>
                      {McpEn.cancel}
                    </Button>
                  </div>
                </section>
              )}
              {ActiveInvocationId === null ? null : (
                <section aria-live="polite" className="fb-mcp-section">
                  <p>{McpEn.invocationRunning}</p>
                  <Button
                    appearance="secondary"
                    onClick={() =>
                      void Client.cancelInvocation(ActiveInvocationId).catch((Cause: unknown) =>
                        SetError(Cause instanceof Error ? Cause.message : McpEn.error),
                      )
                    }
                  >
                    {McpEn.cancelInvocation}
                  </Button>
                </section>
              )}
              {Events.length > 0 ? (
                <section aria-labelledby="mcp-results-heading" className="fb-mcp-section">
                  <h3 id="mcp-results-heading">{McpEn.results}</h3>
                  <div aria-live="polite">
                    {Events.map((Event, Index) => (
                      <InvocationResult Event={Event} key={Index} />
                    ))}
                  </div>
                </section>
              ) : null}
            </div>
          )}
        </div>
      ) : null}
      {!Loading && Tab === "activity" ? (
        <section aria-labelledby="mcp-activity-heading">
          <h2 id="mcp-activity-heading">{McpEn.activity}</h2>
          {Snapshot.Activity.length === 0 ? (
            <p className="fb-muted">{McpEn.noActivity}</p>
          ) : (
            <div className="fb-card-list" role="list">
              {Snapshot.Activity.map((Item) => (
                <article className="fb-activity-card" key={Item.Id} role="listitem">
                  <div className="fb-grow">
                    <strong>
                      <Bidi Value={Item.Outcome} />
                    </strong>
                    <span>
                      <Bidi Value={Item.ApplicationId} />
                    </span>
                    <small>
                      {new Date(Item.CreatedAt).toLocaleString()} · {Item.DurationMs} ms
                    </small>
                  </div>
                  {Item.ReasonCode === null ? null : (
                    <Badge appearance="tint">
                      <Bidi Value={Item.ReasonCode} />
                    </Badge>
                  )}
                </article>
              ))}
            </div>
          )}
        </section>
      ) : null}
      {!Loading && Tab === "admin" && IsTenantAdmin ? (
        <AdminSurface
          Busy={Busy}
          onAssign={(TemplateId, PrincipalId, PrincipalKind) => {
            const Template = Snapshot.Templates.find(({ Id }) => Id === TemplateId);
            return Template === undefined
              ? Promise.reject(new Error(McpEn.managedTemplateUnavailable))
              : Mutate(() => Client.assignTemplate(Template, PrincipalId, PrincipalKind));
          }}
          onBlock={(Kind, Value, Reason) =>
            Mutate(() => Client.createBlockRule(Kind, Value, Reason))
          }
          onService={(Name, SpiffeUri) =>
            Mutate(() => Client.createServiceIdentity(Name, SpiffeUri))
          }
          onServiceGrant={(
            ServiceId,
            RegistrationId,
            CapabilityKind,
            CapabilityName,
            CapabilityFingerprint,
            ApplicationId,
            ExpiresAt,
          ) => {
            const Service = Snapshot.ServiceIdentities.find(({ Id }) => Id === ServiceId);
            return Service === undefined
              ? Promise.reject(new Error(McpEn.serviceUnavailable))
              : Mutate(() =>
                  Client.createServiceInvocationGrant(
                    Service,
                    RegistrationId,
                    CapabilityKind,
                    CapabilityName,
                    CapabilityFingerprint,
                    ApplicationId,
                    ExpiresAt,
                  ),
                );
          }}
          onTemplate={(Name, Endpoint, Profile) =>
            Mutate(() => Client.createTemplate(Name, Endpoint, Profile))
          }
          Snapshot={Snapshot}
        />
      ) : null}
      {Busy ? (
        <div className="fb-working" role="status">
          <Spinner size="tiny" />
          <span>{McpEn.working}</span>
        </div>
      ) : null}
    </section>
  );
}
