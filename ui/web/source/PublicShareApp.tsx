// SPDX-License-Identifier: Apache-2.0

import { Button, Spinner } from "@fluentui/react-components";
import { Download, FileCheck2, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import { BidiText, BrandMark, FileBeltIcon, FileBeltProvider } from "@filebelt/design-system";

import type { PublicShareClient, PublicShareGrant } from "./client.js";
import { en } from "./strings.js";

function formatBytes(value: number): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1, notation: "compact", style: "unit", unit: "byte", unitDisplay: "narrow" }).format(value);
}

export function parsePublicShareFragment(fragment: string): string {
  const value = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  const parameters = new URLSearchParams(value);
  return parameters.get("token") ?? value;
}

export function takePublicShareFragment(): string {
  const fragment = window.location.hash;
  window.history.replaceState({}, "", `${window.location.pathname}${window.location.search}`);
  return parsePublicShareFragment(fragment);
}

export function PublicShareApp({ client, fragmentToken }: { client: PublicShareClient; fragmentToken: string }): ReactNode {
  const [grant, setGrant] = useState<PublicShareGrant | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const exchangeStarted = useRef(false);

  useEffect(() => {
    if (exchangeStarted.current) return;
    exchangeStarted.current = true;
    if (fragmentToken.length === 0) {
      setError(en.publicExpired);
      setBusy(false);
      return;
    }
    void client.exchangePublicShare(fragmentToken).then(setGrant).catch(() => setError(en.publicExpired)).finally(() => setBusy(false));
  }, [client, fragmentToken]);

  const download = async (): Promise<void> => {
    if (grant === null) return;
    setBusy(true);
    try {
      const url = URL.createObjectURL(await client.downloadPublic(grant.exchangeId));
      const anchor = document.createElement("a");
      anchor.download = grant.name;
      anchor.href = url;
      anchor.click();
      URL.revokeObjectURL(url);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FileBeltProvider density="comfortable" themeChoice="system">
      <main className="fb-public-shell">
        <div className="fb-public-brand"><BrandMark /><span>{en.appName}</span></div>
        <section aria-labelledby="public-share-heading" className="fb-public-card">
          <div className="fb-public-icon"><FileBeltIcon icon={grant === null ? ShieldCheck : FileCheck2} size={36} /></div>
          <p className="fb-eyebrow">{en.publicShare}</p>
          <h1 id="public-share-heading">{busy && grant === null ? en.publicLoading : grant === null ? en.publicExpired : <BidiText>{grant.name}</BidiText>}</h1>
          {busy && grant === null ? <Spinner label={en.publicLoading} /> : null}
          {error === null ? null : <p className="fb-error" role="alert">{error}</p>}
          {grant === null ? null : <><p className="fb-muted">{formatBytes(grant.size)} · expires <time dateTime={grant.expiresAt}>{new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(grant.expiresAt))}</time></p><Button appearance="primary" disabled={busy} icon={<Download />} onClick={() => void download()}>{en.publicDownload}</Button></>}
          <p className="fb-public-notice"><FileBeltIcon icon={ShieldCheck} size={16} /> {en.publicShareNotice}</p>
        </section>
      </main>
    </FileBeltProvider>
  );
}
