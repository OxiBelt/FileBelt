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
  CredentialId: string;
  Generation: number;
  KerberosPrincipal: string;
  PrincipalId: string;
  ProjectedGid: number;
  ProjectedUid: number;
}

export interface NfsAdminSnapshot {
  Exports: readonly NfsExportView[];
  Feature: NfsFeatureView;
  Mappings: readonly NfsMappingView[];
  PosixGroups: readonly NfsPosixGroupView[];
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

export interface NfsMappingUpsert {
  AllowedDriveIds: readonly string[];
  ExpectedGeneration: number | null;
  KerberosPrincipal: string;
  PrincipalId: string;
  ProjectedGid: number;
  ProjectedUid: number;
}

export interface NfsAdminClient {
  getOverview(Signal?: AbortSignal): Promise<NfsAdminSnapshot>;
  registerExport(Input: NfsExportRegistration): Promise<void>;
  registerPosixGroup(Input: NfsPosixGroupRegistration): Promise<void>;
  revokeMapping(CredentialId: string, ExpectedGeneration: number): Promise<void>;
  transitionExport(DriveId: string, ExpectedGeneration: number, TargetState: NfsExportState): Promise<void>;
  transitionFeature(ExpectedGeneration: number, TargetState: NfsFeatureState): Promise<void>;
  upsertMapping(Input: NfsMappingUpsert): Promise<void>;
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
        OnRegisterExport={(Input) => Mutate(() => Client.registerExport(Input), Strings.nfsExportRegistered)}
        OnRegisterPosixGroup={(Input) => Mutate(() => Client.registerPosixGroup(Input), Strings.nfsGroupRegistered)}
        OnRevokeMapping={(CredentialId, Generation) => Mutate(() => Client.revokeMapping(CredentialId, Generation), Strings.nfsMappingRevoked)}
        OnTransitionExport={(DriveId, Generation, State) => Mutate(() => Client.transitionExport(DriveId, Generation, State), Strings.nfsExportTransitioned)}
        OnTransitionFeature={(Generation, State) => Mutate(() => Client.transitionFeature(Generation, State), Strings.nfsFeatureTransitioned)}
        OnUpsertMapping={(Input) => Mutate(() => Client.upsertMapping(Input), Strings.nfsMappingSaved)}
        Snapshot={Snapshot}
      />
      <div aria-atomic="true" aria-live="polite" className="fb-sr-only">{Announcement}</div>
    </>
  );
}

interface OverviewProps {
  Busy: boolean;
  OnRegisterExport(Input: NfsExportRegistration): Promise<void>;
  OnRegisterPosixGroup(Input: NfsPosixGroupRegistration): Promise<void>;
  OnRevokeMapping(CredentialId: string, ExpectedGeneration: number): Promise<void>;
  OnTransitionExport(DriveId: string, ExpectedGeneration: number, TargetState: NfsExportState): Promise<void>;
  OnTransitionFeature(ExpectedGeneration: number, TargetState: NfsFeatureState): Promise<void>;
  OnUpsertMapping(Input: NfsMappingUpsert): Promise<void>;
  Snapshot: NfsAdminSnapshot;
}

export function NfsAdminOverviewView({
  Busy,
  OnRegisterExport,
  OnRegisterPosixGroup,
  OnRevokeMapping,
  OnTransitionExport,
  OnTransitionFeature,
  OnUpsertMapping,
  Snapshot,
}: OverviewProps): ReactNode {
  const Feature = Snapshot.Feature;
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
        <FeatureTransitionControls Busy={Busy} Feature={Feature} OnTransition={OnTransitionFeature} />
      </section>

      <div className="fb-nfs-grid">
        <ExportRegistrationForm Busy={Busy} OnRegister={OnRegisterExport} />
        <PosixGroupRegistrationForm Busy={Busy} OnRegister={OnRegisterPosixGroup} />
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
              <ExportTransitionControls Busy={Busy} Export={Export} FeatureState={Feature.State} OnTransition={OnTransitionExport} />
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

      <MappingForm Busy={Busy} Exports={Snapshot.Exports} OnUpsert={OnUpsertMapping} />

      <section aria-labelledby="nfs-mappings-heading" className="fb-nfs-section">
        <div><h3 id="nfs-mappings-heading">{Strings.nfsMappings}</h3><p className="fb-muted">{Strings.nfsMappingsHelp}</p></div>
        <div className="fb-card-list" role="list">
          {Snapshot.Mappings.map((Mapping) => (
            <MappingCard Busy={Busy} key={Mapping.CredentialId} Mapping={Mapping} OnRevoke={OnRevokeMapping} />
          ))}
          {Snapshot.Mappings.length === 0 ? <p>{Strings.nfsNoMappings}</p> : null}
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

function FeatureTransitionControls({ Busy, Feature, OnTransition }: {
  Busy: boolean;
  Feature: NfsFeatureView;
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
            <Button appearance={State === "active" ? "primary" : "secondary"} disabled={Busy || (RequiresConfirmation && !Confirmed)} key={State} onClick={() => { if (RequiresConfirmation) SetConfirmed(false); void OnTransition(Feature.Generation, State); }}>
              {Strings.nfsTransitionTo(State)}
            </Button>
          );
        })}
      </div>
    </div>
  );
}

function ExportTransitionControls({ Busy, Export, FeatureState, OnTransition }: {
  Busy: boolean;
  Export: NfsExportView;
  FeatureState: NfsFeatureState;
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
            <Button appearance={State === "active" ? "primary" : "secondary"} disabled={Busy || (RequiresConfirmation && !Confirmed)} key={State} onClick={() => { if (RequiresConfirmation) SetConfirmed(false); void OnTransition(Export.DriveId, Export.DesiredGeneration, State); }}>
              {Strings.nfsTransitionTo(State)}
            </Button>
          );
        })}
      </div>
    </div>
  );
}

function ExportRegistrationForm({ Busy, OnRegister }: { Busy: boolean; OnRegister(Input: NfsExportRegistration): Promise<void> }): ReactNode {
  const [DriveId, SetDriveId] = useState("");
  const [ExportId, SetExportId] = useState("");
  const Submit = (Event: FormEvent): void => {
    Event.preventDefault();
    const ParsedExportId = PositiveInteger(ExportId);
    if (ParsedExportId === null) return;
    void OnRegister({ DriveId: DriveId.trim(), ExportId: ParsedExportId });
  };
  return (
    <form aria-labelledby="nfs-register-export-heading" className="fb-nfs-card fb-nfs-form" onSubmit={Submit}>
      <div><h3 id="nfs-register-export-heading">{Strings.nfsRegisterExport}</h3><p className="fb-muted">{Strings.nfsRegisterExportHelp}</p></div>
      <label>{Strings.nfsDriveId}<Input disabled={Busy} onChange={(Ignored, Data) => SetDriveId(Data.value)} required value={DriveId} /></label>
      <label>{Strings.nfsExportId}<Input disabled={Busy} inputMode="numeric" onChange={(Ignored, Data) => SetExportId(Data.value)} required type="number" value={ExportId} /></label>
      <Button appearance="primary" disabled={Busy || DriveId.trim().length === 0 || PositiveInteger(ExportId) === null} icon={<Plus aria-hidden="true" />} type="submit">{Strings.register}</Button>
    </form>
  );
}

function PosixGroupRegistrationForm({ Busy, OnRegister }: { Busy: boolean; OnRegister(Input: NfsPosixGroupRegistration): Promise<void> }): ReactNode {
  const [GroupId, SetGroupId] = useState("");
  const [PosixName, SetPosixName] = useState("");
  const [ProjectedGid, SetProjectedGid] = useState("");
  const Submit = (Event: FormEvent): void => {
    Event.preventDefault();
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
      <Button appearance="primary" disabled={Busy || GroupId.trim().length === 0 || PosixName.trim().length === 0 || ProjectedId(ProjectedGid) === null} icon={<Plus aria-hidden="true" />} type="submit">{Strings.register}</Button>
    </form>
  );
}

function MappingForm({ Busy, Exports, OnUpsert }: { Busy: boolean; Exports: readonly NfsExportView[]; OnUpsert(Input: NfsMappingUpsert): Promise<void> }): ReactNode {
  const [PrincipalId, SetPrincipalId] = useState("");
  const [KerberosPrincipal, SetKerberosPrincipal] = useState("");
  const [ProjectedUid, SetProjectedUid] = useState("");
  const [ProjectedGid, SetProjectedGid] = useState("");
  const [ExpectedGeneration, SetExpectedGeneration] = useState("");
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
    const Uid = ProjectedId(ProjectedUid);
    const Gid = ProjectedId(ProjectedGid);
    const Generation = ExpectedGeneration.length === 0 ? null : PositiveInteger(ExpectedGeneration);
    if (Uid === null || Gid === null || (ExpectedGeneration.length > 0 && Generation === null)) return;
    if (!Confirmed) return;
    SetConfirmed(false);
    void OnUpsert({
      AllowedDriveIds: [...AllowedDriveIds],
      ExpectedGeneration: Generation,
      KerberosPrincipal: KerberosPrincipal.trim(),
      PrincipalId: PrincipalId.trim(),
      ProjectedGid: Gid,
      ProjectedUid: Uid,
    });
  };
  return (
    <section aria-labelledby="nfs-map-principal-heading" className="fb-nfs-section">
      <div><h3 id="nfs-map-principal-heading">{Strings.nfsMapPrincipal}</h3><p className="fb-muted">{Strings.nfsExactRealmHelp}</p></div>
      <form className="fb-nfs-card fb-nfs-form" onSubmit={Submit}>
        <label>{Strings.nfsPrincipalId}<Input disabled={Busy} onChange={(Ignored, Data) => SetPrincipalId(Data.value)} required value={PrincipalId} /></label>
        <label>{Strings.nfsKerberosPrincipal}<Input aria-describedby="nfs-exact-realm-help" disabled={Busy} onChange={(Ignored, Data) => SetKerberosPrincipal(Data.value)} placeholder="user@CONFIGURED.REALM" required value={KerberosPrincipal} /></label>
        <p className="fb-muted" id="nfs-exact-realm-help">{Strings.nfsKerberosPrincipalHelp}</p>
        <div className="fb-nfs-form-row">
          <label>{Strings.nfsProjectedUid}<Input disabled={Busy} inputMode="numeric" onChange={(Ignored, Data) => SetProjectedUid(Data.value)} required type="number" value={ProjectedUid} /></label>
          <label>{Strings.nfsProjectedGid}<Input disabled={Busy} inputMode="numeric" onChange={(Ignored, Data) => SetProjectedGid(Data.value)} required type="number" value={ProjectedGid} /></label>
          <label>{Strings.nfsExpectedGeneration}<Input disabled={Busy} inputMode="numeric" onChange={(Ignored, Data) => SetExpectedGeneration(Data.value)} type="number" value={ExpectedGeneration} /></label>
        </div>
        <fieldset className="fb-mount-drives">
          <legend>{Strings.nfsAllowedExports}</legend>
          {Exports.map((Export) => <Checkbox checked={AllowedDriveIds.has(Export.DriveId)} disabled={Busy} key={Export.DriveId} label={`${Export.ExportPath} (${Export.DriveId})`} onChange={(Ignored, Data) => ToggleDrive(Export.DriveId, Data.checked === true)} />)}
          {Exports.length === 0 ? <p>{Strings.nfsNoExportsForMapping}</p> : null}
        </fieldset>
        <p className="fb-muted" id="nfs-mapping-authority-help"><ShieldCheck aria-hidden="true" size={16} /> {Strings.nfsMappingUpdateHelp}</p>
        <Checkbox aria-describedby="nfs-mapping-authority-help" checked={Confirmed} disabled={Busy} label={Strings.nfsConfirmMappingChange} onChange={(Ignored, Data) => SetConfirmed(Data.checked === true)} />
        <Button aria-describedby="nfs-mapping-authority-help" appearance="primary" disabled={Busy || !Confirmed || PrincipalId.trim().length === 0 || KerberosPrincipal.trim().length === 0 || ProjectedId(ProjectedUid) === null || ProjectedId(ProjectedGid) === null || AllowedDriveIds.size === 0} type="submit">{ExpectedGeneration.length === 0 ? Strings.nfsCreateMapping : Strings.nfsUpdateMapping}</Button>
      </form>
    </section>
  );
}

function MappingCard({ Busy, Mapping, OnRevoke }: {
  Busy: boolean;
  Mapping: NfsMappingView;
  OnRevoke(CredentialId: string, ExpectedGeneration: number): Promise<void>;
}): ReactNode {
  const [Confirmed, SetConfirmed] = useState(false);
  const HelpId = `nfs-revoke-${Mapping.CredentialId}-help`;
  return (
    <article className="fb-nfs-card" role="listitem">
      <div className="fb-nfs-card-heading"><div><strong><bdi dir="auto">{Mapping.KerberosPrincipal}</bdi></strong><p className="fb-muted">{Strings.nfsPrincipalId} <bdi dir="auto">{Mapping.PrincipalId}</bdi></p></div><Badge appearance="tint">{Strings.nfsGeneration} {Mapping.Generation}</Badge></div>
      <span>{Strings.nfsProjectedUid} {Mapping.ProjectedUid} · {Strings.nfsProjectedGid} {Mapping.ProjectedGid}</span>
      <p className="fb-muted" id={HelpId}>{Strings.nfsRevokeMappingHelp}</p>
      <Checkbox aria-describedby={HelpId} checked={Confirmed} disabled={Busy} label={Strings.nfsConfirmMappingRevoke} onChange={(Ignored, Data) => SetConfirmed(Data.checked === true)} />
      <Button aria-describedby={HelpId} appearance="secondary" disabled={Busy || !Confirmed} onClick={() => { SetConfirmed(false); void OnRevoke(Mapping.CredentialId, Mapping.Generation); }}>{Strings.revoke}</Button>
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
