// SPDX-License-Identifier: Apache-2.0

import { Button, Select, Spinner } from "@fluentui/react-components";
import { Copy, RotateCcw } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";

import { BidiText, StatusPill } from "@filebelt/design-system";

import type { FileBeltClient, TextComparison } from "./client.js";
import type { FileEntry, VersionRecord } from "./model.js";

function ShortOid(Value: string): string {
  return Value.slice(0, 12);
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns nested props and the restore callback is a receiver-free parent function.
export function TextHistory({
  Client,
  Entry,
  OnRestore,
}: {
  Client: FileBeltClient;
  Entry: FileEntry;
  OnRestore(VersionId: string): Promise<void>;
}): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const [Versions, SetVersions] = useState<readonly VersionRecord[]>([]);
  const [Cursor, SetCursor] = useState<string | null | undefined>(undefined);
  const [BaseVersionId, SetBaseVersionId] = useState("");
  const [TargetVersionId, SetTargetVersionId] = useState("");
  const [Comparison, SetComparison] = useState<TextComparison | null>(null);
  const [ErrorMessage, SetError] = useState<string | null>(null);
  const [Loading, SetLoading] = useState(false);
  const LoadingReference = useRef(false);
  const RequestGeneration = useRef(0);
  const ComparisonTooLarge = ErrorMessage !== null && /too[ ._-]*large/i.test(ErrorMessage);
  const LoadPage = useCallback(
    async (PageCursor: string | null, Generation: number): Promise<void> => {
      if (LoadingReference.current) return;
      LoadingReference.current = true;
      SetLoading(true);
      try {
        const Page = await Client.listTextVersions(Entry.Id, PageCursor);
        if (Generation !== RequestGeneration.current) return;
        SetVersions((Current) => {
          const ById = new Map(Current.map((Version) => [Version.Id, Version]));
          for (const Version of Page.Items) ById.set(Version.Id, Version);
          return [...ById.values()];
        });
        SetCursor(Page.NextCursor);
        SetError(null);
        SetBaseVersionId((Current) =>
          Current.length === 0 ? (Page.Items.at(-1)?.Id ?? "") : Current,
        );
        SetTargetVersionId((Current) =>
          Current.length === 0 ? (Page.Items.at(0)?.Id ?? "") : Current,
        );
      } catch (Cause) {
        if (Generation === RequestGeneration.current)
          SetError(Cause instanceof Error ? Cause.message : "History is unavailable.");
      } finally {
        if (Generation === RequestGeneration.current) {
          LoadingReference.current = false;
          SetLoading(false);
        }
      }
    },
    [Client, Entry.Id],
  );

  useEffect(() => {
    const Generation = RequestGeneration.current + 1;
    RequestGeneration.current = Generation;
    LoadingReference.current = false;
    SetVersions([]);
    SetCursor(undefined);
    SetBaseVersionId("");
    SetTargetVersionId("");
    SetComparison(null);
    SetError(null);
    void LoadPage(null, Generation);
    return () => {
      RequestGeneration.current += 1;
    };
  }, [Entry.Id, LoadPage]);

  const Compare = async (): Promise<void> => {
    if (BaseVersionId.length === 0 || TargetVersionId.length === 0) return;
    SetError(null);
    try {
      SetComparison(await Client.compareTextVersions(Entry.Id, BaseVersionId, TargetVersionId));
    } catch (Cause) {
      SetComparison(null);
      SetError(
        Cause instanceof Error ? Cause.message : "The selected versions cannot be compared inline.",
      );
    }
  };

  return (
    <section aria-labelledby="text-history-heading" className="fb-text-history">
      <header className="fb-page-heading">
        <div>
          <h1 id="text-history-heading">Text history</h1>
          <p className="fb-muted">
            <BidiText>{Entry.Name}</BidiText>
          </p>
        </div>
      </header>
      {ErrorMessage === null ? null : (
        <p role="alert">
          {ComparisonTooLarge
            ? "The selected versions are too large to compare inline. Download either version to compare locally."
            : ErrorMessage}
        </p>
      )}
      <div className="fb-card-list" role="list">
        {Versions.map((Version, Index) => (
          <article className="fb-activity-card fb-history-row" key={Version.Id} role="listitem">
            <div className="fb-grow">
              <strong>Version {Version.Version}</strong>
              <span className="fb-muted">
                {Version.Author} · {new Date(Version.CreatedAt).toLocaleString()}
              </span>
            </div>
            {Version.RevisionBackend === undefined || Version.RevisionBackend === null ? null : (
              <StatusPill Kind="informative">{Version.RevisionBackend}</StatusPill>
            )}
            {Version.ObservedContentClass === undefined ||
            Version.ObservedContentClass === null ? null : (
              <StatusPill Kind="subtle">{Version.ObservedContentClass}</StatusPill>
            )}
            {Version.GitCommitOid === null || Version.GitCommitOid === undefined ? null : (
              <Button
                aria-label={`Copy full commit identifier ${Version.GitCommitOid}`}
                icon={<Copy aria-hidden="true" />}
                onClick={() => {
                  const GitCommitOid = Version.GitCommitOid;
                  const ClipboardApi = navigator.clipboard as Clipboard | undefined;
                  if (
                    GitCommitOid !== null &&
                    GitCommitOid !== undefined &&
                    ClipboardApi !== undefined
                  )
                    void ClipboardApi.writeText(GitCommitOid);
                }}
                title={Version.GitCommitOid}
              >
                {ShortOid(Version.GitCommitOid)}
              </Button>
            )}
            {Index === 0 ? (
              <StatusPill Kind="brand">Current</StatusPill>
            ) : (
              <Button
                appearance="secondary"
                icon={<RotateCcw aria-hidden="true" />}
                onClick={() => void OnRestore(Version.Id)}
              >
                Restore as new version
              </Button>
            )}
          </article>
        ))}
      </div>
      {Cursor === undefined ? <Spinner label="Loading history" /> : null}
      {typeof Cursor !== "string" ? null : (
        <Button disabled={Loading} onClick={() => void LoadPage(Cursor, RequestGeneration.current)}>
          Load more versions
        </Button>
      )}
      {Versions.length < 2 ? null : (
        <div className="fb-history-compare">
          <label htmlFor="history-base">
            Base version
            <Select
              id="history-base"
              onChange={(Event) => {
                SetBaseVersionId(Event.currentTarget.value);
              }}
              value={BaseVersionId}
            >
              {Versions.map((Version) => (
                <option key={Version.Id} value={Version.Id}>
                  Version {Version.Version}
                </option>
              ))}
            </Select>
          </label>
          <label htmlFor="history-target">
            Target version
            <Select
              id="history-target"
              onChange={(Event) => {
                SetTargetVersionId(Event.currentTarget.value);
              }}
              value={TargetVersionId}
            >
              {Versions.map((Version) => (
                <option key={Version.Id} value={Version.Id}>
                  Version {Version.Version}
                </option>
              ))}
            </Select>
          </label>
          <Button disabled={BaseVersionId === TargetVersionId} onClick={() => void Compare()}>
            Compare versions
          </Button>
        </div>
      )}
      {Comparison === null ? null : (
        <pre aria-label="Version comparison" className="fb-text-diff">
          {Comparison.Hunks.flatMap((Hunk, HunkIndex) =>
            Hunk.Lines.map((Line, LineIndex) => (
              <code className={`is-${Line.Kind}`} key={`${HunkIndex}-${LineIndex}`}>
                {Line.Text}
                {"\n"}
              </code>
            )),
          )}
        </pre>
      )}
    </section>
  );
}
