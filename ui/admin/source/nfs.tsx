// SPDX-License-Identifier: Apache-2.0

import { Badge, Button, Checkbox, Input, Spinner } from "@fluentui/react-components";
import { Network, Plus, RefreshCw, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import type { FormEvent, ReactNode } from "react";

import { AdminEn as Strings } from "./strings.js";

export type NfsFeatureState = "active" | "disabled" | "draining" | "preflight";
export type NfsExportState = "active" | "disabled" | "draining";

export interface NfsFeatureView {
  AppliedGatewayEpoch: number | null;
  AppliedGatewayId: string | null;
  AppliedManifestGeneration: number;
  DesiredManifestGeneration: number;
  Generation: number;
  ManifestApplied: boolean;
  RestoreGeneration: number;
  State: NfsFeatureState;
}

export interface NfsExportView {
  AppliedGeneration: number;
  AppliedState: NfsExportState;
  DesiredGeneration: number;
  DesiredState: NfsExportState;
  DriveId: string;
  ExportId: number;
  ExportPath: string;
  InSync: boolean;
}

export interface NfsPosixGroupView {
  GroupId: string;
  PosixName: string;
  ProjectedGid: number;
}

export interface NfsMappingView {
  AllowedDriveIds?: readonly string[];
  CredentialId: string;
  Generation: number;
  KerberosPrincipal: string;
  PrincipalId: string;
  ProjectedGid: number;
  ProjectedUid: number;
}

export type NfsMappingProposalState = "approved" | "cancelled" | "declined" | "expired" | "pending";

export interface NfsMappingProposalView {
  AllowedDriveIds: readonly string[];
  CreatedAt: string;
  DecidedAt: string | null;
  ExpiresAt: string;
  Generation: number;
  Id: string;
  KerberosPrincipal: string;
  PrincipalId: string;
  ProjectedGid: number;
  ProjectedUid: number;
  ProposerPrincipalId: string;
  State: NfsMappingProposalState;
}

export interface NfsQuarantinedMappingView extends NfsMappingView {
  QuarantineReason: string;
  QuarantinedAt: string;
}

export interface NfsConflictView {
  BaseVersionId: string | null;
  ConflictCopyNodeId: string | null;
  ConflictCopyVersionId: string | null;
  CreatedAt: string;
  DriveId: string;
  ExpectedHeadVersionId: string | null;
  ExpiresAt: string;
  Id: string;
  LogicalSizeBytes: number;
  ObservedHeadVersionId: string | null;
  SourceNodeId: string;
  State: "retained";
  WriteSessionId: string;
}

export interface NfsAdminSnapshot {
  Conflicts: readonly NfsConflictView[];
  Exports: readonly NfsExportView[];
  Feature: NfsFeatureView;
  Mappings: readonly NfsMappingView[];
  PendingProposals: readonly NfsMappingProposalView[];
  PosixGroups: readonly NfsPosixGroupView[];
  QuarantinedMappings: readonly NfsQuarantinedMappingView[];
  Realm: string;
  TenantSlug: string;
}

export interface NfsExportRegistration {
  DriveId: string;
  ExportId: number;
}

export interface NfsPosixGroupRegistration {
  GroupId: string;
  PosixName: string;
  ProjectedGid: number;
}

export interface NfsMappingProposalCreate {
  AllowedDriveIds: readonly string[];
  KerberosPrincipal: string;
  PrincipalId: string;
  ProjectedGid: number;
  ProjectedUid: number;
}

/** @deprecated Direct mapping upserts are disabled; use this shape to create a proposal. */
export type NfsMappingUpsert = NfsMappingProposalCreate;

export interface NfsConflictCopy {
  DisplayName: string;
  DriveId: string;
  ExpectedParentGeneration: number;
  ParentId: string;
}

export interface NfsAdminClient {
  attenuateMappingScope(CredentialId: string, AllowedDriveIds: readonly string[], ExpectedGeneration: number, ConfirmTenant: string): Promise<void>;
  cancelProposal(ProposalId: string, ExpectedGeneration: number, ConfirmTenant: string): Promise<void>;
  getOverview(Signal?: AbortSignal): Promise<NfsAdminSnapshot>;
  copyConflict(ConflictId: string, Input: NfsConflictCopy, ConfirmTenant: string): Promise<void>;
  discardConflict(ConflictId: string, ConfirmTenant: string): Promise<void>;
  registerExport(Input: NfsExportRegistration, ConfirmTenant: string): Promise<void>;
  registerPosixGroup(Input: NfsPosixGroupRegistration, ConfirmTenant: string): Promise<void>;
  revokeMapping(CredentialId: string, ExpectedGeneration: number, ConfirmTenant: string): Promise<void>;
  transitionExport(DriveId: string, ExpectedGeneration: number, TargetState: NfsExportState, ConfirmTenant: string): Promise<void>;
  transitionFeature(ExpectedGeneration: number, TargetState: NfsFeatureState, ConfirmTenant: string): Promise<void>;
  proposeMapping(Input: NfsMappingProposalCreate, ConfirmTenant: string): Promise<void>;
}

export class NfsReauthenticationRequiredError extends Error {
  constructor() {
    super(Strings.nfsReauthenticationRequired);
    this.name = "NfsReauthenticationRequiredError";
  }
}

function IsNfsReauthenticationRequired(Cause: unknown): boolean {
  return Cause instanceof NfsReauthenticationRequiredError
    || (Cause instanceof Error && Cause.name === "NfsReauthenticationRequiredError");
}

export function FeatureTransitions(State: NfsFeatureState): readonly NfsFeatureState[] {
  switch (State) {
    case "disabled": return ["preflight"];
    case "preflight": return ["disabled", "active"];
    case "active": return ["draining"];
    case "draining": return ["disabled"];
  }
}

export function ExportTransitions(
  Export: NfsExportView,
  FeatureState: NfsFeatureState,
): readonly NfsExportState[] {
  if (FeatureState !== "preflight" && FeatureState !== "draining") return [];
  switch (Export.DesiredState) {
    case "disabled": return ["active"];
    case "active": return ["draining"];
    case "draining":
      return Export.AppliedState === "draining"
        && Export.AppliedGeneration === Export.DesiredGeneration
        ? ["active", "disabled"]
        : ["active"];
  }
}

export function NfsAdminSurface({ Client }: { Client: NfsAdminClient }): ReactNode {
  const [Snapshot, SetSnapshot] = useState<NfsAdminSnapshot | null>(null);
  const [Busy, SetBusy] = useState(false);
  const [ErrorMessage, SetErrorMessage] = useState<string | null>(null);
  const [ReauthenticationRequired, SetReauthenticationRequired] = useState(false);
  const [Announcement, SetAnnouncement] = useState("");

  const Refresh = useCallback(async (Signal?: AbortSignal): Promise<void> => {
    try {
      SetSnapshot(await Client.getOverview(Signal));
      SetErrorMessage(null);
      SetReauthenticationRequired(false);
    } catch (Cause) {
      if (Cause instanceof DOMException && Cause.name === "AbortError") return;
      if (IsNfsReauthenticationRequired(Cause)) SetReauthenticationRequired(true);
      else SetErrorMessage(Cause instanceof Error ? Cause.message : Strings.nfsUnavailable);
    }
  }, [Client]);

  useEffect(() => {
    const Controller = new AbortController();
    void Refresh(Controller.signal);
    return () => Controller.abort();
  }, [Refresh]);

  const Mutate = async (Operation: () => Promise<void>, Message: string): Promise<void> => {
    SetBusy(true);
    SetErrorMessage(null);
    SetReauthenticationRequired(false);
    try {
      await Operation();
      await Refresh();
      SetAnnouncement(Message);
    } catch (Cause) {
      if (IsNfsReauthenticationRequired(Cause)) SetReauthenticationRequired(true);
      else SetErrorMessage(Cause instanceof Error ? Cause.message : Strings.nfsMutationFailed);
    } finally {
      SetBusy(false);
    }
  };

  if (Snapshot === null && ErrorMessage === null && !ReauthenticationRequired) {
    return <section aria-busy="true" aria-label={Strings.nfsAdministration}><Spinner label={Strings.nfsLoading} /></section>;
  }

  if (Snapshot === null) {
    return (
      <section aria-labelledby="nfs-admin-unavailable-heading" className="fb-nfs-admin">
        <h2 id="nfs-admin-unavailable-heading">{Strings.nfsAdministration}</h2>
        {ErrorMessage === null ? null : <div className="fb-error" role="alert">{ErrorMessage}</div>}
        {ReauthenticationRequired ? <ReauthenticationNotice /> : null}
        <Button appearance="primary" icon={<RefreshCw aria-hidden="true" />} onClick={() => void Refresh()}>{Strings.tryAgain}</Button>
      </section>
    );
  }

  return (
    <>
      {ErrorMessage === null ? null : <div className="fb-error" role="alert">{ErrorMessage}</div>}
      {ReauthenticationRequired ? <ReauthenticationNotice /> : null}
      <NfsAdminOverviewView
        Busy={Busy}
        OnCopyConflict={(ConflictId, Input, ConfirmTenant) => Mutate(() => Client.copyConflict(ConflictId, Input, ConfirmTenant), Strings.nfsConflictCopied)}
        OnDiscardConflict={(ConflictId, ConfirmTenant) => Mutate(() => Client.discardConflict(ConflictId, ConfirmTenant), Strings.nfsConflictDiscarded)}
        OnRegisterExport={(Input, ConfirmTenant) => Mutate(() => Client.registerExport(Input, ConfirmTenant), Strings.nfsExportRegistered)}
        OnRegisterPosixGroup={(Input, ConfirmTenant) => Mutate(() => Client.registerPosixGroup(Input, ConfirmTenant), Strings.nfsGroupRegistered)}
        OnAttenuateMapping={(CredentialId, DriveIds, Generation, ConfirmTenant) => Mutate(() => Client.attenuateMappingScope(CredentialId, DriveIds, Generation, ConfirmTenant), Strings.nfsMappingAttenuated)}
        OnCancelProposal={(ProposalId, Generation, ConfirmTenant) => Mutate(() => Client.cancelProposal(ProposalId, Generation, ConfirmTenant), Strings.nfsProposalCancelled)}
        OnProposeMapping={(Input, ConfirmTenant) => Mutate(() => Client.proposeMapping(Input, ConfirmTenant), Strings.nfsProposalCreated)}
        OnRevokeMapping={(CredentialId, Generation, ConfirmTenant) => Mutate(() => Client.revokeMapping(CredentialId, Generation, ConfirmTenant), Strings.nfsMappingRevoked)}
        OnTransitionExport={(DriveId, Generation, State, ConfirmTenant) => Mutate(() => Client.transitionExport(DriveId, Generation, State, ConfirmTenant), Strings.nfsExportTransitioned)}
        OnTransitionFeature={(Generation, State, ConfirmTenant) => Mutate(() => Client.transitionFeature(Generation, State, ConfirmTenant), Strings.nfsFeatureTransitioned)}
        Snapshot={Snapshot}
      />
      <div aria-atomic="true" aria-live="polite" className="fb-sr-only">{Announcement}</div>
    </>
  );
}

interface OverviewProps {
  Busy: boolean;
  OnAttenuateMapping(CredentialId: string, AllowedDriveIds: readonly string[], ExpectedGeneration: number, ConfirmTenant: string): Promise<void>;
  OnCancelProposal(ProposalId: string, ExpectedGeneration: number, ConfirmTenant: string): Promise<void>;
  OnCopyConflict(ConflictId: string, Input: NfsConflictCopy, ConfirmTenant: string): Promise<void>;
  OnDiscardConflict(ConflictId: string, ConfirmTenant: string): Promise<void>;
  OnRegisterExport(Input: NfsExportRegistration, ConfirmTenant: string): Promise<void>;
  OnRegisterPosixGroup(Input: NfsPosixGroupRegistration, ConfirmTenant: string): Promise<void>;
  OnRevokeMapping(CredentialId: string, ExpectedGeneration: number, ConfirmTenant: string): Promise<void>;
  OnTransitionExport(DriveId: string, ExpectedGeneration: number, TargetState: NfsExportState, ConfirmTenant: string): Promise<void>;
  OnTransitionFeature(ExpectedGeneration: number, TargetState: NfsFeatureState, ConfirmTenant: string): Promise<void>;
  OnProposeMapping(Input: NfsMappingProposalCreate, ConfirmTenant: string): Promise<void>;
  Snapshot: NfsAdminSnapshot;
}

export function NfsAdminOverviewView({
  Busy,
  OnAttenuateMapping,
  OnCancelProposal,
  OnCopyConflict,
  OnDiscardConflict,
  OnRegisterExport,
  OnRegisterPosixGroup,
  OnRevokeMapping,
  OnTransitionExport,
  OnTransitionFeature,
  OnProposeMapping,
  Snapshot,
}: OverviewProps): ReactNode {
  const [TenantConfirmation, SetTenantConfirmation] = useState("");
  const Feature = Snapshot.Feature;
  const TenantConfirmed = TenantConfirmation === Snapshot.TenantSlug;
  const ConfirmedMutation = async (Operation: (Confirmation: string) => Promise<void>): Promise<void> => {
    if (!TenantConfirmed) return;
    const Confirmation = TenantConfirmation;
    SetTenantConfirmation("");
    await Operation(Confirmation);
  };
  return (
    <section aria-labelledby="nfs-admin-heading" className="fb-nfs-admin">
      <header className="fb-nfs-heading">
        <div>
          <p className="fb-eyebrow"><Network aria-hidden="true" size={18} /> {Strings.nfsNetworkStorage}</p>
          <h2 id="nfs-admin-heading">{Strings.nfsAdministration}</h2>
          <p className="fb-muted">{Strings.nfsSafetyNotice}</p>
        </div>
        <Badge appearance="tint" color={Feature.ManifestApplied ? "success" : "warning"}>
          {Feature.ManifestApplied ? Strings.nfsManifestApplied : Strings.nfsManifestPending}
        </Badge>
      </header>

      <section aria-labelledby="nfs-tenant-confirmation-heading" className="fb-nfs-card">
        <h3 id="nfs-tenant-confirmation-heading">{Strings.nfsTenantConfirmation}</h3>
        <label htmlFor="nfs-tenant-confirmation">{Strings.nfsTenantConfirmationLabel(Snapshot.TenantSlug)}</label>
        <Input
          aria-describedby="nfs-tenant-confirmation-help"
          autoComplete="off"
          disabled={Busy}
          id="nfs-tenant-confirmation"
          onChange={(Ignored, Data) => SetTenantConfirmation(Data.value)}
          spellCheck={false}
          value={TenantConfirmation}
        />
        <p className="fb-muted" id="nfs-tenant-confirmation-help">{Strings.nfsTenantConfirmationHelp}</p>
      </section>

      <section aria-labelledby="nfs-feature-heading" className="fb-nfs-card">
        <div className="fb-nfs-card-heading">
          <div><h3 id="nfs-feature-heading">{Strings.nfsFeature}</h3><p className="fb-muted">{Strings.nfsFeatureHelp}</p></div>
          <Badge appearance="tint">{Feature.State}</Badge>
        </div>
        <dl className="fb-nfs-generation-grid">
          <Generation Label={Strings.nfsFeatureGeneration} Value={Feature.Generation} />
          <Generation Label={Strings.nfsDesiredManifestGeneration} Value={Feature.DesiredManifestGeneration} />
          <Generation Label={Strings.nfsAppliedManifestGeneration} Value={Feature.AppliedManifestGeneration} />
          <Generation Label={Strings.nfsRestoreGeneration} Value={Feature.RestoreGeneration} />
          <div><dt>{Strings.nfsAppliedGateway}</dt><dd><bdi dir="auto">{Feature.AppliedGatewayId ?? Strings.none}</bdi>{Feature.AppliedGatewayEpoch === null ? null : ` · ${Strings.nfsEpoch} ${Feature.AppliedGatewayEpoch}`}</dd></div>
        </dl>
        <FeatureTransitionControls Busy={Busy} Feature={Feature} MutationEnabled={TenantConfirmed} OnTransition={(Generation, State) => ConfirmedMutation((Confirmation) => OnTransitionFeature(Generation, State, Confirmation))} />
      </section>

      <div className="fb-nfs-grid">
        <ExportRegistrationForm Busy={Busy} MutationEnabled={TenantConfirmed} OnRegister={(Input) => ConfirmedMutation((Confirmation) => OnRegisterExport(Input, Confirmation))} />
        <PosixGroupRegistrationForm Busy={Busy} MutationEnabled={TenantConfirmed} OnRegister={(Input) => ConfirmedMutation((Confirmation) => OnRegisterPosixGroup(Input, Confirmation))} />
      </div>

      <section aria-labelledby="nfs-exports-heading" className="fb-nfs-section">
        <div><h3 id="nfs-exports-heading">{Strings.nfsExports}</h3><p className="fb-muted">{Strings.nfsExportsHelp}</p></div>
        <div className="fb-card-list" role="list">
          {Snapshot.Exports.map((Export) => (
            <article className="fb-nfs-card" key={Export.DriveId} role="listitem">
              <div className="fb-nfs-card-heading">
                <div><strong><bdi dir="auto">{Export.ExportPath}</bdi></strong><p className="fb-muted">{Strings.nfsExportId} {Export.ExportId} · {Strings.nfsDriveId} <bdi dir="auto">{Export.DriveId}</bdi></p></div>
                <Badge appearance="tint" color={Export.InSync ? "success" : "warning"}>{Export.InSync ? Strings.nfsApplied : Strings.nfsPending}</Badge>
              </div>
              <dl className="fb-nfs-generation-grid">
                <div><dt>{Strings.nfsDesiredState}</dt><dd>{Export.DesiredState}</dd></div>
                <Generation Label={Strings.nfsDesiredGeneration} Value={Export.DesiredGeneration} />
                <div><dt>{Strings.nfsAppliedState}</dt><dd>{Export.AppliedState}</dd></div>
                <Generation Label={Strings.nfsAppliedGeneration} Value={Export.AppliedGeneration} />
              </dl>
              <ExportTransitionControls Busy={Busy} Export={Export} FeatureState={Feature.State} MutationEnabled={TenantConfirmed} OnTransition={(DriveId, Generation, State) => ConfirmedMutation((Confirmation) => OnTransitionExport(DriveId, Generation, State, Confirmation))} />
            </article>
          ))}
          {Snapshot.Exports.length === 0 ? <p>{Strings.nfsNoExports}</p> : null}
        </div>
      </section>

      <section aria-labelledby="nfs-groups-heading" className="fb-nfs-section">
        <div><h3 id="nfs-groups-heading">{Strings.nfsPosixGroups}</h3><p className="fb-muted">{Strings.nfsGroupsHelp}</p></div>
        <div className="fb-card-list" role="list">
          {Snapshot.PosixGroups.map((Group) => <article className="fb-nfs-card" key={Group.GroupId} role="listitem"><strong><bdi dir="auto">{Group.PosixName}</bdi></strong><span>{Strings.nfsProjectedGid} {Group.ProjectedGid}</span><span className="fb-muted"><bdi dir="auto">{Group.GroupId}</bdi></span></article>)}
          {Snapshot.PosixGroups.length === 0 ? <p>{Strings.nfsNoPosixGroups}</p> : null}
        </div>
      </section>

      <MappingProposalForm Busy={Busy} Exports={Snapshot.Exports} MutationEnabled={TenantConfirmed} OnPropose={(Input) => ConfirmedMutation((Confirmation) => OnProposeMapping(Input, Confirmation))} Realm={Snapshot.Realm} />

      <section aria-labelledby="nfs-proposals-heading" className="fb-nfs-section">
        <div><h3 id="nfs-proposals-heading">{Strings.nfsPendingProposals}</h3><p className="fb-muted">{Strings.nfsPendingProposalsHelp}</p></div>
        <div className="fb-card-list" role="list">
          {Snapshot.PendingProposals.map((Proposal) => (
            <ProposalCard Busy={Busy} key={Proposal.Id} MutationEnabled={TenantConfirmed} OnCancel={(ProposalId, Generation) => ConfirmedMutation((Confirmation) => OnCancelProposal(ProposalId, Generation, Confirmation))} Proposal={Proposal} />
          ))}
          {Snapshot.PendingProposals.length === 0 ? <p>{Strings.nfsNoPendingProposals}</p> : null}
        </div>
      </section>

      <section aria-labelledby="nfs-quarantine-heading" className="fb-nfs-section">
        <div><h3 id="nfs-quarantine-heading">{Strings.nfsQuarantinedMappings}</h3><p className="fb-muted">{Strings.nfsQuarantinedMappingsHelp}</p></div>
        <div className="fb-card-list" role="list">
          {Snapshot.QuarantinedMappings.map((Mapping) => <QuarantinedMappingCard key={Mapping.CredentialId} Mapping={Mapping} />)}
          {Snapshot.QuarantinedMappings.length === 0 ? <p>{Strings.nfsNoQuarantinedMappings}</p> : null}
        </div>
      </section>

      <section aria-labelledby="nfs-mappings-heading" className="fb-nfs-section">
        <div><h3 id="nfs-mappings-heading">{Strings.nfsMappings}</h3><p className="fb-muted">{Strings.nfsMappingsHelp}</p></div>
        <div className="fb-card-list" role="list">
          {Snapshot.Mappings.map((Mapping) => (
            <MappingCard Busy={Busy} Exports={Snapshot.Exports} key={Mapping.CredentialId} Mapping={Mapping} MutationEnabled={TenantConfirmed} OnAttenuate={(CredentialId, DriveIds, Generation) => ConfirmedMutation((Confirmation) => OnAttenuateMapping(CredentialId, DriveIds, Generation, Confirmation))} OnRevoke={(CredentialId, Generation) => ConfirmedMutation((Confirmation) => OnRevokeMapping(CredentialId, Generation, Confirmation))} />
          ))}
          {Snapshot.Mappings.length === 0 ? <p>{Strings.nfsNoMappings}</p> : null}
        </div>
      </section>

      <section aria-labelledby="nfs-conflicts-heading" className="fb-nfs-section">
        <div><h3 id="nfs-conflicts-heading">{Strings.nfsConflicts}</h3><p className="fb-muted">{Strings.nfsConflictsHelp}</p></div>
        <div className="fb-card-list" role="list">
          {Snapshot.Conflicts.map((Conflict) => (
            <ConflictCard
              Busy={Busy}
              Conflict={Conflict}
              key={Conflict.Id}
              MutationEnabled={TenantConfirmed}
              OnCopy={(Input) => ConfirmedMutation((Confirmation) => OnCopyConflict(Conflict.Id, Input, Confirmation))}
              OnDiscard={() => ConfirmedMutation((Confirmation) => OnDiscardConflict(Conflict.Id, Confirmation))}
            />
          ))}
          {Snapshot.Conflicts.length === 0 ? <p>{Strings.nfsNoConflicts}</p> : null}
        </div>
      </section>
    </section>
  );
}

function ReauthenticationNotice(): ReactNode {
  return <div className="fb-mount-reauth" role="alert"><p>{Strings.nfsReauthenticationRequired}</p><Button appearance="primary" as="a" href="/api/v1/auth/login?return_path=%2Fadmin">{Strings.signInAgain}</Button></div>;
}

function Generation({ Label, Value }: { Label: string; Value: number }): ReactNode {
  return <div><dt>{Label}</dt><dd>{Value}</dd></div>;
}

function FeatureTransitionControls({ Busy, Feature, MutationEnabled, OnTransition }: {
  Busy: boolean;
  Feature: NfsFeatureView;
  MutationEnabled: boolean;
  OnTransition(ExpectedGeneration: number, TargetState: NfsFeatureState): Promise<void>;
}): ReactNode {
  const [Confirmed, SetConfirmed] = useState(false);
  const Transitions = FeatureTransitions(Feature.State);
  const HasConsequentialTransition = Transitions.some((State) => State !== "preflight");
  return (
    <div className="fb-nfs-confirmation">
      {HasConsequentialTransition ? <Checkbox checked={Confirmed} disabled={Busy} label={Strings.nfsConfirmFeatureTransition} onChange={(Ignored, Data) => SetConfirmed(Data.checked === true)} /> : null}
      <div className="fb-nfs-actions">
        {Transitions.map((State) => {
          const RequiresConfirmation = State !== "preflight";
          return (
            <Button appearance={State === "active" ? "primary" : "secondary"} disabled={Busy || !MutationEnabled || (RequiresConfirmation && !Confirmed)} key={State} onClick={() => { if (RequiresConfirmation) SetConfirmed(false); void OnTransition(Feature.Generation, State); }}>
              {Strings.nfsTransitionTo(State)}
            </Button>
          );
        })}
      </div>
    </div>
  );
}

function ExportTransitionControls({ Busy, Export, FeatureState, MutationEnabled, OnTransition }: {
  Busy: boolean;
  Export: NfsExportView;
  FeatureState: NfsFeatureState;
  MutationEnabled: boolean;
  OnTransition(DriveId: string, ExpectedGeneration: number, TargetState: NfsExportState): Promise<void>;
}): ReactNode {
  const [Confirmed, SetConfirmed] = useState(false);
  const Transitions = ExportTransitions(Export, FeatureState);
  const HasConsequentialTransition = Transitions.some((State) => State === "draining" || State === "disabled");
  if (Transitions.length === 0) return <span className="fb-muted">{Strings.nfsNoExportTransition}</span>;
  return (
    <div className="fb-nfs-confirmation">
      {HasConsequentialTransition ? <Checkbox checked={Confirmed} disabled={Busy} label={Strings.nfsConfirmExportTransition} onChange={(Ignored, Data) => SetConfirmed(Data.checked === true)} /> : null}
      <div className="fb-nfs-actions">
        {Transitions.map((State) => {
          const RequiresConfirmation = State === "draining" || State === "disabled";
          return (
            <Button appearance={State === "active" ? "primary" : "secondary"} disabled={Busy || !MutationEnabled || (RequiresConfirmation && !Confirmed)} key={State} onClick={() => { if (RequiresConfirmation) SetConfirmed(false); void OnTransition(Export.DriveId, Export.DesiredGeneration, State); }}>
              {Strings.nfsTransitionTo(State)}
            </Button>
          );
        })}
      </div>
    </div>
  );
}

function ExportRegistrationForm({ Busy, MutationEnabled, OnRegister }: { Busy: boolean; MutationEnabled: boolean; OnRegister(Input: NfsExportRegistration): Promise<void> }): ReactNode {
  const [DriveId, SetDriveId] = useState("");
  const [ExportId, SetExportId] = useState("");
  const Submit = (Event: FormEvent): void => {
    Event.preventDefault();
    if (!MutationEnabled) return;
    const ParsedExportId = PositiveInteger(ExportId);
    if (ParsedExportId === null) return;
    void OnRegister({ DriveId: DriveId.trim(), ExportId: ParsedExportId });
  };
  return (
    <form aria-labelledby="nfs-register-export-heading" className="fb-nfs-card fb-nfs-form" onSubmit={Submit}>
      <div><h3 id="nfs-register-export-heading">{Strings.nfsRegisterExport}</h3><p className="fb-muted">{Strings.nfsRegisterExportHelp}</p></div>
      <label>{Strings.nfsDriveId}<Input disabled={Busy} onChange={(Ignored, Data) => SetDriveId(Data.value)} required value={DriveId} /></label>
      <label>{Strings.nfsExportId}<Input disabled={Busy} inputMode="numeric" onChange={(Ignored, Data) => SetExportId(Data.value)} required type="number" value={ExportId} /></label>
      <Button appearance="primary" disabled={Busy || !MutationEnabled || DriveId.trim().length === 0 || PositiveInteger(ExportId) === null} icon={<Plus aria-hidden="true" />} type="submit">{Strings.register}</Button>
    </form>
  );
}

function PosixGroupRegistrationForm({ Busy, MutationEnabled, OnRegister }: { Busy: boolean; MutationEnabled: boolean; OnRegister(Input: NfsPosixGroupRegistration): Promise<void> }): ReactNode {
  const [GroupId, SetGroupId] = useState("");
  const [PosixName, SetPosixName] = useState("");
  const [ProjectedGid, SetProjectedGid] = useState("");
  const Submit = (Event: FormEvent): void => {
    Event.preventDefault();
    if (!MutationEnabled) return;
    const ParsedGid = ProjectedId(ProjectedGid);
    if (ParsedGid === null) return;
    void OnRegister({ GroupId: GroupId.trim(), PosixName: PosixName.trim(), ProjectedGid: ParsedGid });
  };
  return (
    <form aria-labelledby="nfs-register-group-heading" className="fb-nfs-card fb-nfs-form" onSubmit={Submit}>
      <div><h3 id="nfs-register-group-heading">{Strings.nfsRegisterPosixGroup}</h3><p className="fb-muted">{Strings.nfsRegisterGroupHelp}</p></div>
      <label>{Strings.nfsGroupId}<Input disabled={Busy} onChange={(Ignored, Data) => SetGroupId(Data.value)} required value={GroupId} /></label>
      <label>{Strings.nfsPosixName}<Input disabled={Busy} maxLength={255} onChange={(Ignored, Data) => SetPosixName(Data.value)} pattern="[a-z_][a-z0-9_.-]{0,254}" required value={PosixName} /></label>
      <label>{Strings.nfsProjectedGid}<Input disabled={Busy} inputMode="numeric" onChange={(Ignored, Data) => SetProjectedGid(Data.value)} required type="number" value={ProjectedGid} /></label>
      <Button appearance="primary" disabled={Busy || !MutationEnabled || GroupId.trim().length === 0 || PosixName.trim().length === 0 || ProjectedId(ProjectedGid) === null} icon={<Plus aria-hidden="true" />} type="submit">{Strings.register}</Button>
    </form>
  );
}

function MappingProposalForm({ Busy, Exports, MutationEnabled, OnPropose, Realm }: { Busy: boolean; Exports: readonly NfsExportView[]; MutationEnabled: boolean; OnPropose(Input: NfsMappingProposalCreate): Promise<void>; Realm: string }): ReactNode {
  const [PrincipalId, SetPrincipalId] = useState("");
  const [KerberosPrincipal, SetKerberosPrincipal] = useState("");
  const [ProjectedUid, SetProjectedUid] = useState("");
  const [ProjectedGid, SetProjectedGid] = useState("");
  const [AllowedDriveIds, SetAllowedDriveIds] = useState<ReadonlySet<string>>(() => new Set());
  const [Confirmed, SetConfirmed] = useState(false);
  const ToggleDrive = (DriveId: string, Checked: boolean): void => {
    SetAllowedDriveIds((Current) => {
      const Next = new Set(Current);
      if (Checked) Next.add(DriveId);
      else Next.delete(DriveId);
      return Next;
    });
  };
  const Submit = (Event: FormEvent): void => {
    Event.preventDefault();
    if (!MutationEnabled) return;
    const Uid = ProjectedId(ProjectedUid);
    const Gid = ProjectedId(ProjectedGid);
    if (Uid === null || Gid === null) return;
    if (!Confirmed) return;
    SetConfirmed(false);
    void OnPropose({
      AllowedDriveIds: [...AllowedDriveIds],
      KerberosPrincipal: KerberosPrincipal.trim(),
      PrincipalId: PrincipalId.trim(),
      ProjectedGid: Gid,
      ProjectedUid: Uid,
    });
  };
  return (
    <section aria-labelledby="nfs-map-principal-heading" className="fb-nfs-section">
      <div><h3 id="nfs-map-principal-heading">{Strings.nfsProposeMapping}</h3><p className="fb-muted">{Strings.nfsExactRealmHelp} {Strings.nfsConfiguredRealm}: <bdi dir="auto">{Realm}</bdi>.</p></div>
      <form className="fb-nfs-card fb-nfs-form" onSubmit={Submit}>
        <label>{Strings.nfsPrincipalId}<Input disabled={Busy} onChange={(Ignored, Data) => SetPrincipalId(Data.value)} required value={PrincipalId} /></label>
        <label>{Strings.nfsKerberosPrincipal}<Input aria-describedby="nfs-exact-realm-help" disabled={Busy} onChange={(Ignored, Data) => SetKerberosPrincipal(Data.value)} placeholder={`user@${Realm}`} required value={KerberosPrincipal} /></label>
        <p className="fb-muted" id="nfs-exact-realm-help">{Strings.nfsKerberosPrincipalHelp}</p>
        <div className="fb-nfs-form-row">
          <label>{Strings.nfsProjectedUid}<Input disabled={Busy} inputMode="numeric" onChange={(Ignored, Data) => SetProjectedUid(Data.value)} required type="number" value={ProjectedUid} /></label>
          <label>{Strings.nfsProjectedGid}<Input disabled={Busy} inputMode="numeric" onChange={(Ignored, Data) => SetProjectedGid(Data.value)} required type="number" value={ProjectedGid} /></label>
        </div>
        <fieldset className="fb-mount-drives">
          <legend>{Strings.nfsAllowedExports}</legend>
          {Exports.map((Export) => <Checkbox checked={AllowedDriveIds.has(Export.DriveId)} disabled={Busy} key={Export.DriveId} label={`${Export.ExportPath} (${Export.DriveId})`} onChange={(Ignored, Data) => ToggleDrive(Export.DriveId, Data.checked === true)} />)}
          {Exports.length === 0 ? <p>{Strings.nfsNoExportsForMapping}</p> : null}
        </fieldset>
        <p className="fb-muted" id="nfs-mapping-authority-help"><ShieldCheck aria-hidden="true" size={16} /> {Strings.nfsProposalHelp}</p>
        <Checkbox aria-describedby="nfs-mapping-authority-help" checked={Confirmed} disabled={Busy} label={Strings.nfsConfirmProposal} onChange={(Ignored, Data) => SetConfirmed(Data.checked === true)} />
        <Button aria-describedby="nfs-mapping-authority-help" appearance="primary" disabled={Busy || !MutationEnabled || !Confirmed || PrincipalId.trim().length === 0 || KerberosPrincipal.trim().length === 0 || ProjectedId(ProjectedUid) === null || ProjectedId(ProjectedGid) === null || AllowedDriveIds.size === 0} type="submit">{Strings.nfsCreateProposal}</Button>
      </form>
    </section>
  );
}

function MappingCard({ Busy, Exports, Mapping, MutationEnabled, OnAttenuate, OnRevoke }: {
  Busy: boolean;
  Exports: readonly NfsExportView[];
  Mapping: NfsMappingView;
  MutationEnabled: boolean;
  OnAttenuate(CredentialId: string, AllowedDriveIds: readonly string[], ExpectedGeneration: number): Promise<void>;
  OnRevoke(CredentialId: string, ExpectedGeneration: number): Promise<void>;
}): ReactNode {
  const [Confirmed, SetConfirmed] = useState(false);
  const [AllowedDriveIds, SetAllowedDriveIds] = useState<ReadonlySet<string>>(() => new Set(Mapping.AllowedDriveIds ?? []));
  const HelpId = `nfs-revoke-${Mapping.CredentialId}-help`;
  const CurrentDriveIds = Mapping.AllowedDriveIds ?? [];
  const IsStrictAttenuation = AllowedDriveIds.size > 0
    && AllowedDriveIds.size < CurrentDriveIds.length
    && [...AllowedDriveIds].every((DriveId) => CurrentDriveIds.includes(DriveId));
  const ToggleDrive = (DriveId: string, Checked: boolean): void => SetAllowedDriveIds((Current) => {
    const Next = new Set(Current);
    if (Checked) Next.add(DriveId);
    else Next.delete(DriveId);
    return Next;
  });
  return (
    <article className="fb-nfs-card" role="listitem">
      <div className="fb-nfs-card-heading"><div><strong><bdi dir="auto">{Mapping.KerberosPrincipal}</bdi></strong><p className="fb-muted">{Strings.nfsPrincipalId} <bdi dir="auto">{Mapping.PrincipalId}</bdi></p></div><Badge appearance="tint">{Strings.nfsGeneration} {Mapping.Generation}</Badge></div>
      <span>{Strings.nfsProjectedUid} {Mapping.ProjectedUid} · {Strings.nfsProjectedGid} {Mapping.ProjectedGid}</span>
      <span className="fb-muted">{Strings.nfsAllowedExports}: {Mapping.AllowedDriveIds === undefined ? Strings.nfsAllowedExportsUnknown : Mapping.AllowedDriveIds.map((DriveId) => <bdi dir="auto" key={DriveId}>{DriveId} </bdi>)}</span>
      {Mapping.AllowedDriveIds === undefined ? null : (
        <fieldset className="fb-mount-drives">
          <legend>{Strings.nfsAttenuateScope}</legend>
          {Exports.filter(({ DriveId }) => CurrentDriveIds.includes(DriveId)).map((Export) => <Checkbox checked={AllowedDriveIds.has(Export.DriveId)} disabled={Busy} key={Export.DriveId} label={`${Export.ExportPath} (${Export.DriveId})`} onChange={(Ignored, Data) => ToggleDrive(Export.DriveId, Data.checked === true)} />)}
          <Button appearance="secondary" disabled={Busy || !MutationEnabled || !IsStrictAttenuation} onClick={() => void OnAttenuate(Mapping.CredentialId, [...AllowedDriveIds], Mapping.Generation)}>{Strings.nfsSaveAttenuatedScope}</Button>
        </fieldset>
      )}
      <p className="fb-muted" id={HelpId}>{Strings.nfsRevokeMappingHelp}</p>
      <Checkbox aria-describedby={HelpId} checked={Confirmed} disabled={Busy} label={Strings.nfsConfirmMappingRevoke} onChange={(Ignored, Data) => SetConfirmed(Data.checked === true)} />
      <Button aria-describedby={HelpId} appearance="secondary" disabled={Busy || !MutationEnabled || !Confirmed} onClick={() => { SetConfirmed(false); void OnRevoke(Mapping.CredentialId, Mapping.Generation); }}>{Strings.revoke}</Button>
    </article>
  );
}

function ProposalCard({ Busy, MutationEnabled, OnCancel, Proposal }: {
  Busy: boolean;
  MutationEnabled: boolean;
  OnCancel(ProposalId: string, ExpectedGeneration: number): Promise<void>;
  Proposal: NfsMappingProposalView;
}): ReactNode {
  const [Confirmed, SetConfirmed] = useState(false);
  const HelpId = `nfs-cancel-proposal-${Proposal.Id}-help`;
  return (
    <article className="fb-nfs-card" role="listitem">
      <div className="fb-nfs-card-heading"><div><strong><bdi dir="auto">{Proposal.KerberosPrincipal}</bdi></strong><p className="fb-muted">{Strings.nfsPrincipalId} <bdi dir="auto">{Proposal.PrincipalId}</bdi></p></div><Badge appearance="tint" color="warning">{Proposal.State}</Badge></div>
      <span>{Strings.nfsProjectedUid} {Proposal.ProjectedUid} · {Strings.nfsProjectedGid} {Proposal.ProjectedGid}</span>
      <span className="fb-muted">{Strings.nfsProposalId} <bdi dir="auto">{Proposal.Id}</bdi> · {Strings.nfsProposedBy} <bdi dir="auto">{Proposal.ProposerPrincipalId}</bdi></span>
      <span className="fb-muted">{Strings.nfsAllowedExports}: {Proposal.AllowedDriveIds.map((DriveId) => <bdi dir="auto" key={DriveId}>{DriveId} </bdi>)}</span>
      <span className="fb-muted">{Strings.nfsProposalCreatedAt} <time dateTime={Proposal.CreatedAt}>{Proposal.CreatedAt}</time> · {Strings.nfsProposalExpires} <time dateTime={Proposal.ExpiresAt}>{Proposal.ExpiresAt}</time> · {Strings.nfsGeneration} {Proposal.Generation}</span>
      <p className="fb-muted" id={HelpId}>{Strings.nfsCancelProposalHelp}</p>
      <Checkbox aria-describedby={HelpId} checked={Confirmed} disabled={Busy} label={Strings.nfsConfirmProposalCancel} onChange={(Ignored, Data) => SetConfirmed(Data.checked === true)} />
      <Button appearance="secondary" aria-describedby={HelpId} disabled={Busy || !MutationEnabled || !Confirmed} onClick={() => { SetConfirmed(false); void OnCancel(Proposal.Id, Proposal.Generation); }}>{Strings.cancel}</Button>
    </article>
  );
}

function QuarantinedMappingCard({ Mapping }: { Mapping: NfsQuarantinedMappingView }): ReactNode {
  return (
    <article className="fb-nfs-card" role="listitem">
      <div className="fb-nfs-card-heading"><div><strong><bdi dir="auto">{Mapping.KerberosPrincipal}</bdi></strong><p className="fb-muted">{Strings.nfsPrincipalId} <bdi dir="auto">{Mapping.PrincipalId}</bdi></p></div><Badge appearance="tint" color="danger">{Strings.nfsQuarantined}</Badge></div>
      <span>{Strings.nfsProjectedUid} {Mapping.ProjectedUid} · {Strings.nfsProjectedGid} {Mapping.ProjectedGid}</span>
      <span className="fb-muted">{Strings.nfsAllowedExports}: {Mapping.AllowedDriveIds?.map((DriveId) => <bdi dir="auto" key={DriveId}>{DriveId} </bdi>) ?? Strings.nfsAllowedExportsUnknown}</span>
      <span className="fb-muted">{Strings.nfsQuarantinedAt} <time dateTime={Mapping.QuarantinedAt}>{Mapping.QuarantinedAt}</time></span>
      <span className="fb-muted">{Strings.nfsQuarantineReason}: <bdi dir="auto">{Mapping.QuarantineReason}</bdi></span>
    </article>
  );
}

function ConflictCard({ Busy, Conflict, MutationEnabled, OnCopy, OnDiscard }: {
  Busy: boolean;
  Conflict: NfsConflictView;
  MutationEnabled: boolean;
  OnCopy(Input: NfsConflictCopy): Promise<void>;
  OnDiscard(): Promise<void>;
}): ReactNode {
  const [DisplayName, SetDisplayName] = useState("");
  const [ExpectedParentGeneration, SetExpectedParentGeneration] = useState("");
  const [ParentId, SetParentId] = useState("");
  const [DiscardConfirmed, SetDiscardConfirmed] = useState(false);
  const HelpId = `nfs-conflict-${Conflict.Id}-help`;
  const Submit = (Event: FormEvent): void => {
    Event.preventDefault();
    if (!MutationEnabled) return;
    const Generation = PositiveInteger(ExpectedParentGeneration);
    if (Generation === null || ParentId.trim().length === 0 || DisplayName.trim().length === 0) return;
    void OnCopy({
      DisplayName,
      DriveId: Conflict.DriveId,
      ExpectedParentGeneration: Generation,
      ParentId: ParentId.trim(),
    });
  };
  return (
    <article className="fb-nfs-card" role="listitem">
      <div className="fb-nfs-card-heading">
        <div><strong>{Strings.nfsConflict}</strong><p className="fb-muted"><bdi dir="auto">{Conflict.Id}</bdi></p></div>
        <Badge appearance="tint" color="warning">{Strings.nfsRetained}</Badge>
      </div>
      <dl className="fb-nfs-generation-grid">
        <div><dt>{Strings.nfsDriveId}</dt><dd><bdi dir="auto">{Conflict.DriveId}</bdi></dd></div>
        <div><dt>{Strings.nfsSourceNodeId}</dt><dd><bdi dir="auto">{Conflict.SourceNodeId}</bdi></dd></div>
        <div><dt>{Strings.nfsLogicalSize}</dt><dd>{Conflict.LogicalSizeBytes}</dd></div>
        <div><dt>{Strings.nfsConflictExpires}</dt><dd><time dateTime={Conflict.ExpiresAt}>{Conflict.ExpiresAt}</time></dd></div>
      </dl>
      <form aria-describedby={HelpId} className="fb-nfs-form" onSubmit={Submit}>
        <p className="fb-muted" id={HelpId}>{Strings.nfsConflictCopyHelp}</p>
        <label>{Strings.nfsParentId}<Input disabled={Busy} onChange={(Ignored, Data) => SetParentId(Data.value)} required value={ParentId} /></label>
        <label>{Strings.nfsConflictCopyName}<Input disabled={Busy} maxLength={255} onChange={(Ignored, Data) => SetDisplayName(Data.value)} required value={DisplayName} /></label>
        <label>{Strings.nfsExpectedParentGeneration}<Input disabled={Busy} inputMode="numeric" onChange={(Ignored, Data) => SetExpectedParentGeneration(Data.value)} required type="number" value={ExpectedParentGeneration} /></label>
        <Button appearance="primary" disabled={Busy || !MutationEnabled || ParentId.trim().length === 0 || DisplayName.trim().length === 0 || PositiveInteger(ExpectedParentGeneration) === null} type="submit">{Strings.nfsCopyConflict}</Button>
      </form>
      <Checkbox aria-describedby={HelpId} checked={DiscardConfirmed} disabled={Busy} label={Strings.nfsConfirmConflictDiscard} onChange={(Ignored, Data) => SetDiscardConfirmed(Data.checked === true)} />
      <Button appearance="secondary" disabled={Busy || !MutationEnabled || !DiscardConfirmed} onClick={() => { SetDiscardConfirmed(false); void OnDiscard(); }}>{Strings.nfsDiscardConflict}</Button>
    </article>
  );
}

function PositiveInteger(Value: string): number | null {
  const Parsed = Number(Value);
  return Number.isSafeInteger(Parsed) && Parsed > 0 ? Parsed : null;
}

function ProjectedId(Value: string): number | null {
  const Parsed = PositiveInteger(Value);
  return Parsed !== null && Parsed <= 4_294_967_294 && Parsed !== 65_534 ? Parsed : null;
}
