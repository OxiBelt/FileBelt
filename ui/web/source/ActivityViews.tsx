// SPDX-License-Identifier: Apache-2.0

import { Button, Input, ProgressBar } from "@fluentui/react-components";
import { BellRing, Clock3, Link2, RotateCcw, ShieldCheck, UploadCloud } from "lucide-react";
import { useState } from "react";
import type { FormEvent, ReactNode } from "react";

import { BidiText, FileBeltIcon, StatusPill } from "@filebelt/design-system";

import type { CreateShareInput } from "./client.js";
import type { FileEntry, PrivacyEvent, SessionRecord, ShareRecord, UploadRecord, VersionRecord } from "./model.js";
import type { Strings } from "./strings.js";

function FormatBytes(Value: number): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1, notation: "compact", style: "unit", unit: "byte", unitDisplay: "narrow" }).format(Value);
}

function FormatDate(Value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(Value));
}

export function UploadsView({ Strings, Uploads }: { Strings: Strings; Uploads: readonly UploadRecord[] }): ReactNode {
  return (
    <section aria-labelledby="uploads-heading" className="fb-activity-view">
      <header className="fb-page-heading"><div><h1 id="uploads-heading">{Strings.uploads}</h1><p className="fb-muted">{Strings.uploadPrivacy}</p></div></header>
      <div className="fb-card-list" role="list">
        {Uploads.map((Upload) => (
          <article className="fb-activity-card" key={Upload.Id} role="listitem">
            <FileBeltIcon Icon={UploadCloud} />
            <div className="fb-grow"><strong><BidiText>{Upload.Name}</BidiText></strong><span className="fb-muted">{FormatBytes(Upload.Size)}</span><ProgressBar aria-label={`${Upload.Name} ${Strings.progress}`} max={1} value={Upload.Progress} /></div>
            <StatusPill Kind={Upload.State === "complete" ? "success" : Upload.State === "failed" ? "danger" : "informative"}>{Upload.State === "complete" ? Strings.ready : Strings.uploading}</StatusPill>
          </article>
        ))}
      </div>
    </section>
  );
}

export function VersionsView({
  File,
  onRestore: OnRestore,
  Strings,
  Versions,
}: {
  File: FileEntry | undefined;
  onRestore(VersionId: string): Promise<void>;
  Strings: Strings;
  Versions: readonly VersionRecord[];
}): ReactNode {
  const Matching = File === undefined ? [] : Versions.filter(({ FileId }) => FileId === File.Id);
  return (
    <section aria-labelledby="versions-heading" className="fb-activity-view">
      <header className="fb-page-heading"><div><h1 id="versions-heading">{Strings.versions}</h1><p className="fb-muted">{File === undefined ? Strings.noVersions : <BidiText>{File.Name}</BidiText>}</p></div></header>
      <div className="fb-card-list" role="list">
        {Matching.map((Version, Index) => (
          <article className="fb-activity-card" key={Version.Id} role="listitem">
            <FileBeltIcon Icon={Clock3} />
            <div className="fb-grow"><strong>{Strings.version} {Version.Version}</strong><span className="fb-muted">{Strings.versionCreator}: <BidiText>{Version.Author}</BidiText> · <time dateTime={Version.CreatedAt}>{FormatDate(Version.CreatedAt)}</time> · {FormatBytes(Version.Size)}</span></div>
            {Index === 0 ? <StatusPill Kind="brand">{Strings.current}</StatusPill> : <Button appearance="secondary" icon={<RotateCcw aria-hidden="true" size={18} strokeWidth={1.75} />} onClick={() => void OnRestore(Version.Id)}>{Strings.restoreVersion}</Button>}
          </article>
        ))}
      </div>
    </section>
  );
}

export function SharesView({
  File,
  onCreate: OnCreate,
  onRevoke: OnRevoke,
  Shares,
  Strings,
}: {
  File: FileEntry | undefined;
  onCreate(Input: CreateShareInput): Promise<void>;
  onRevoke(ShareId: string): Promise<void>;
  Shares: readonly ShareRecord[];
  Strings: Strings;
}): ReactNode {
  const [Permission, SetPermission] = useState<ShareRecord["Permission"]>("Viewer");
  const [Target, SetTarget] = useState("");
  const [Busy, SetBusy] = useState(false);
  const Matching = File === undefined ? Shares : Shares.filter(({ ResourceId }) => ResourceId === File.Id);

  const Submit = async (Event: FormEvent): Promise<void> => {
    Event.preventDefault();
    if (File === undefined || Target.trim().length === 0) return;
    SetBusy(true);
    try {
      await OnCreate({ FileId: File.Id, Kind: "direct", Permission, Target: Target.trim() });
      SetTarget("");
    } finally {
      SetBusy(false);
    }
  };

  return (
    <section aria-labelledby="shares-heading" className="fb-activity-view">
      <header className="fb-page-heading"><div><h1 id="shares-heading">{Strings.shares}</h1><p className="fb-muted">{File === undefined ? Strings.noSelection : <BidiText>{File.Name}</BidiText>}</p></div></header>
      {File !== undefined ? (
        <form className="fb-share-form" onSubmit={(Event) => void Submit(Event)}>
          <label>{Strings.shareTarget}<Input onChange={(Ignored, Data) => SetTarget(Data.value)} value={Target} /></label>
          <label>{Strings.sharePermission}<select onChange={(Event) => SetPermission(Event.currentTarget.value as ShareRecord["Permission"])} value={Permission}><option value="Viewer">{Strings.viewer}</option><option value="Contributor">{Strings.contributor}</option><option value="Manager">{Strings.manager}</option></select></label>
          <Button appearance="primary" disabled={Busy || Target.trim().length === 0} type="submit">{Strings.saveShare}</Button>
        </form>
      ) : null}
      <div className="fb-card-list" role="list">
        {Matching.map((Share) => (
          <article className="fb-activity-card" key={Share.Id} role="listitem">
            <FileBeltIcon Icon={Link2} />
            <div className="fb-grow"><strong><BidiText>{Share.ResourceName}</BidiText></strong><span className="fb-muted"><BidiText>{Share.Target}</BidiText> · {Share.Permission}{Share.ExpiresAt === undefined ? "" : ` · expires ${FormatDate(Share.ExpiresAt)}`}</span></div>
            <Button appearance="secondary" onClick={() => void OnRevoke(Share.Id)}>{Strings.revoke}</Button>
          </article>
        ))}
        {Matching.length === 0 ? <p>{Strings.noShares}</p> : null}
      </div>
    </section>
  );
}

export function SessionsView({ onRevoke: OnRevoke, Sessions, Strings }: { onRevoke(Id: string): Promise<void>; Sessions: readonly SessionRecord[]; Strings: Strings }): ReactNode {
  return (
    <section aria-labelledby="sessions-heading" className="fb-activity-view">
      <header className="fb-page-heading"><div><h1 id="sessions-heading">{Strings.sessions}</h1><p className="fb-muted">{Strings.sessionsDescription}</p></div></header>
      <div className="fb-card-list" role="list">
        {Sessions.map((Session) => (
          <article className="fb-activity-card" key={Session.Id} role="listitem">
            <FileBeltIcon Icon={ShieldCheck} />
            <div className="fb-grow"><strong><BidiText>{Session.Device}</BidiText></strong><span className="fb-muted"><BidiText>{Session.Location}</BidiText> · <time dateTime={Session.LastActiveAt}>{FormatDate(Session.LastActiveAt)}</time></span></div>
            {Session.Current ? <StatusPill Kind="success">{Strings.activeSession}</StatusPill> : <Button appearance="secondary" onClick={() => void OnRevoke(Session.Id)}>{Strings.revoke}</Button>}
          </article>
        ))}
      </div>
    </section>
  );
}

export function PrivacyView({ Events, onMarkRead: OnMarkRead, Strings }: { Events: readonly PrivacyEvent[]; onMarkRead(): Promise<void>; Strings: Strings }): ReactNode {
  return (
    <section aria-labelledby="privacy-heading" className="fb-activity-view">
      <header className="fb-page-heading"><div><h1 id="privacy-heading">{Strings.privacy}</h1><p className="fb-muted">{Strings.privacyDescription}</p></div><Button appearance="secondary" disabled={!Events.some(({ Unread }) => Unread)} onClick={() => void OnMarkRead()}>{Strings.markRead}</Button></header>
      <div className="fb-card-list" role="list">
        {Events.map((Event) => (
          <article className={Event.Unread ? "fb-activity-card is-unread" : "fb-activity-card"} key={Event.Id} role="listitem">
            <FileBeltIcon Icon={BellRing} />
            <div className="fb-grow"><strong><BidiText>{Event.Action}</BidiText></strong><span className="fb-muted"><BidiText>{Event.Actor}</BidiText> · <time dateTime={Event.CreatedAt}>{FormatDate(Event.CreatedAt)}</time></span></div>
            {Event.Unread ? <span className="fb-unread-dot"><span className="fb-sr-only">Unread</span></span> : null}
          </article>
        ))}
        {Events.length === 0 ? <p>{Strings.noPrivacyEvents}</p> : null}
      </div>
    </section>
  );
}
