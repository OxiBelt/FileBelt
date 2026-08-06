// SPDX-License-Identifier: Apache-2.0

import { Button, Input, ProgressBar } from "@fluentui/react-components";
import { BellRing, Clock3, Link2, RotateCcw, ShieldCheck, UploadCloud } from "lucide-react";
import { useState } from "react";
import type { FormEvent, ReactNode } from "react";

import { BidiText, FileBeltIcon, StatusPill } from "@filebelt/design-system";

import type { CreateShareInput } from "./client.js";
import type { FileEntry, PrivacyEvent, SessionRecord, ShareRecord, UploadRecord, VersionRecord } from "./model.js";
import type { Strings } from "./strings.js";

function formatBytes(value: number): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1, notation: "compact", style: "unit", unit: "byte", unitDisplay: "narrow" }).format(value);
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export function UploadsView({ strings, uploads }: { strings: Strings; uploads: readonly UploadRecord[] }): ReactNode {
  return (
    <section aria-labelledby="uploads-heading" className="fb-activity-view">
      <header className="fb-page-heading"><div><h1 id="uploads-heading">{strings.uploads}</h1><p className="fb-muted">{strings.uploadPrivacy}</p></div></header>
      <div className="fb-card-list" role="list">
        {uploads.map((upload) => (
          <article className="fb-activity-card" key={upload.id} role="listitem">
            <FileBeltIcon icon={UploadCloud} />
            <div className="fb-grow"><strong><BidiText>{upload.name}</BidiText></strong><span className="fb-muted">{formatBytes(upload.size)}</span><ProgressBar aria-label={`${upload.name} ${strings.progress}`} max={1} value={upload.progress} /></div>
            <StatusPill kind={upload.state === "complete" ? "success" : upload.state === "failed" ? "danger" : "informative"}>{upload.state === "complete" ? strings.ready : strings.uploading}</StatusPill>
          </article>
        ))}
      </div>
    </section>
  );
}

export function VersionsView({
  file,
  onRestore,
  strings,
  versions,
}: {
  file: FileEntry | undefined;
  onRestore(versionId: string): Promise<void>;
  strings: Strings;
  versions: readonly VersionRecord[];
}): ReactNode {
  const matching = file === undefined ? [] : versions.filter(({ fileId }) => fileId === file.id);
  return (
    <section aria-labelledby="versions-heading" className="fb-activity-view">
      <header className="fb-page-heading"><div><h1 id="versions-heading">{strings.versions}</h1><p className="fb-muted">{file === undefined ? strings.noVersions : <BidiText>{file.name}</BidiText>}</p></div></header>
      <div className="fb-card-list" role="list">
        {matching.map((version, index) => (
          <article className="fb-activity-card" key={version.id} role="listitem">
            <FileBeltIcon icon={Clock3} />
            <div className="fb-grow"><strong>{strings.version} {version.version}</strong><span className="fb-muted">{strings.versionCreator}: <BidiText>{version.author}</BidiText> · <time dateTime={version.createdAt}>{formatDate(version.createdAt)}</time> · {formatBytes(version.size)}</span></div>
            {index === 0 ? <StatusPill kind="brand">{strings.current}</StatusPill> : <Button appearance="secondary" icon={<RotateCcw aria-hidden="true" size={18} strokeWidth={1.75} />} onClick={() => void onRestore(version.id)}>{strings.restoreVersion}</Button>}
          </article>
        ))}
      </div>
    </section>
  );
}

export function SharesView({
  file,
  onCreate,
  onRevoke,
  shares,
  strings,
}: {
  file: FileEntry | undefined;
  onCreate(input: CreateShareInput): Promise<void>;
  onRevoke(shareId: string): Promise<void>;
  shares: readonly ShareRecord[];
  strings: Strings;
}): ReactNode {
  const [permission, setPermission] = useState<ShareRecord["permission"]>("Viewer");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const matching = file === undefined ? shares : shares.filter(({ resourceId }) => resourceId === file.id);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (file === undefined || target.trim().length === 0) return;
    setBusy(true);
    try {
      await onCreate({ fileId: file.id, kind: "direct", permission, target: target.trim() });
      setTarget("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-labelledby="shares-heading" className="fb-activity-view">
      <header className="fb-page-heading"><div><h1 id="shares-heading">{strings.shares}</h1><p className="fb-muted">{file === undefined ? strings.noSelection : <BidiText>{file.name}</BidiText>}</p></div></header>
      {file !== undefined ? (
        <form className="fb-share-form" onSubmit={(event) => void submit(event)}>
          <label>{strings.shareTarget}<Input onChange={(_, data) => setTarget(data.value)} value={target} /></label>
          <label>{strings.sharePermission}<select onChange={(event) => setPermission(event.currentTarget.value as ShareRecord["permission"])} value={permission}><option value="Viewer">{strings.viewer}</option><option value="Contributor">{strings.contributor}</option><option value="Manager">{strings.manager}</option></select></label>
          <Button appearance="primary" disabled={busy || target.trim().length === 0} type="submit">{strings.saveShare}</Button>
        </form>
      ) : null}
      <div className="fb-card-list" role="list">
        {matching.map((share) => (
          <article className="fb-activity-card" key={share.id} role="listitem">
            <FileBeltIcon icon={Link2} />
            <div className="fb-grow"><strong><BidiText>{share.resourceName}</BidiText></strong><span className="fb-muted"><BidiText>{share.target}</BidiText> · {share.permission}{share.expiresAt === undefined ? "" : ` · expires ${formatDate(share.expiresAt)}`}</span></div>
            <Button appearance="secondary" onClick={() => void onRevoke(share.id)}>{strings.revoke}</Button>
          </article>
        ))}
        {matching.length === 0 ? <p>{strings.noShares}</p> : null}
      </div>
    </section>
  );
}

export function SessionsView({ onRevoke, sessions, strings }: { onRevoke(id: string): Promise<void>; sessions: readonly SessionRecord[]; strings: Strings }): ReactNode {
  return (
    <section aria-labelledby="sessions-heading" className="fb-activity-view">
      <header className="fb-page-heading"><div><h1 id="sessions-heading">{strings.sessions}</h1><p className="fb-muted">{strings.sessionsDescription}</p></div></header>
      <div className="fb-card-list" role="list">
        {sessions.map((session) => (
          <article className="fb-activity-card" key={session.id} role="listitem">
            <FileBeltIcon icon={ShieldCheck} />
            <div className="fb-grow"><strong><BidiText>{session.device}</BidiText></strong><span className="fb-muted"><BidiText>{session.location}</BidiText> · <time dateTime={session.lastActiveAt}>{formatDate(session.lastActiveAt)}</time></span></div>
            {session.current ? <StatusPill kind="success">{strings.activeSession}</StatusPill> : <Button appearance="secondary" onClick={() => void onRevoke(session.id)}>{strings.revoke}</Button>}
          </article>
        ))}
      </div>
    </section>
  );
}

export function PrivacyView({ events, onMarkRead, strings }: { events: readonly PrivacyEvent[]; onMarkRead(): Promise<void>; strings: Strings }): ReactNode {
  return (
    <section aria-labelledby="privacy-heading" className="fb-activity-view">
      <header className="fb-page-heading"><div><h1 id="privacy-heading">{strings.privacy}</h1><p className="fb-muted">{strings.privacyDescription}</p></div><Button appearance="secondary" disabled={!events.some(({ unread }) => unread)} onClick={() => void onMarkRead()}>{strings.markRead}</Button></header>
      <div className="fb-card-list" role="list">
        {events.map((event) => (
          <article className={event.unread ? "fb-activity-card is-unread" : "fb-activity-card"} key={event.id} role="listitem">
            <FileBeltIcon icon={BellRing} />
            <div className="fb-grow"><strong><BidiText>{event.action}</BidiText></strong><span className="fb-muted"><BidiText>{event.actor}</BidiText> · <time dateTime={event.createdAt}>{formatDate(event.createdAt)}</time></span></div>
            {event.unread ? <span className="fb-unread-dot"><span className="fb-sr-only">Unread</span></span> : null}
          </article>
        ))}
        {events.length === 0 ? <p>{strings.noPrivacyEvents}</p> : null}
      </div>
    </section>
  );
}
