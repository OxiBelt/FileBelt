// SPDX-License-Identifier: Apache-2.0

import { Button, Select, Spinner } from "@fluentui/react-components";
import { useEffect, useState, type ReactNode } from "react";

import type {
  EditTextLimitBytes,
  FileBeltClient,
  InlineTextLimitBytes,
  TextPreferences,
} from "./client.js";

const MiB = 1024 * 1024;
const EditOptions = [1, 2, 4, 8, 16].map((Value) => Value * MiB) as readonly EditTextLimitBytes[];
const InlineOptions = [8, 16, 32, 64, 100].map(
  (Value) => Value * MiB,
) as readonly InlineTextLimitBytes[];

export function TextSettings({ Client }: { Client: FileBeltClient }): ReactNode {
  const [Etag, SetEtag] = useState<string | null>(null);
  const [Value, SetValue] = useState<TextPreferences | null>(null);
  const [ErrorMessage, SetError] = useState<string | null>(null);
  const [Saving, SetSaving] = useState(false);
  useEffect(() => {
    let Active = true;
    void Client.getTextPreferences()
      .then((Response) => {
        if (!Active) return;
        SetEtag(Response.Etag);
        SetValue(Response.Value);
      })
      .catch((Cause: unknown) => {
        if (Active)
          SetError(Cause instanceof Error ? Cause.message : "Text preferences are unavailable.");
      });
    return () => {
      Active = false;
    };
  }, [Client]);

  const Save = async (): Promise<void> => {
    if (Etag === null || Value === null) return;
    SetSaving(true);
    SetError(null);
    try {
      const Response = await Client.updateTextPreferences(Value, Etag);
      SetEtag(Response.Etag);
      SetValue(Response.Value);
    } catch (Cause) {
      SetError(Cause instanceof Error ? Cause.message : "Text preferences could not be saved.");
    } finally {
      SetSaving(false);
    }
  };

  return (
    <section aria-labelledby="text-settings-heading" className="fb-text-settings">
      <header className="fb-page-heading">
        <div>
          <h1 id="text-settings-heading">Text editing</h1>
          <p className="fb-muted">
            Choose personal source and inline viewing limits. The server enforces these limits for
            every request.
          </p>
        </div>
      </header>
      {ErrorMessage === null ? null : <p role="alert">{ErrorMessage}</p>}
      {Value === null ? <Spinner label="Loading text preferences" /> : null}
      {Value === null ? null : (
        <form
          onSubmit={(Event) => {
            Event.preventDefault();
            void Save();
          }}
        >
          <label htmlFor="text-edit-limit">
            Editable source limit
            <Select
              id="text-edit-limit"
              onChange={(Event) =>
                SetValue((Current) =>
                  Current === null
                    ? Current
                    : {
                        ...Current,
                        EditLimitBytes: Number(Event.currentTarget.value) as EditTextLimitBytes,
                        InlineLimitBytes: Math.max(
                          Current.InlineLimitBytes,
                          Number(Event.currentTarget.value),
                        ) as InlineTextLimitBytes,
                      },
                )
              }
              value={String(Value.EditLimitBytes)}
            >
              {EditOptions.map((Bytes) => (
                <option key={Bytes} value={Bytes}>
                  {Bytes / MiB} MiB
                </option>
              ))}
            </Select>
          </label>
          <label htmlFor="text-inline-limit">
            Inline source limit
            <Select
              id="text-inline-limit"
              onChange={(Event) =>
                SetValue((Current) =>
                  Current === null
                    ? Current
                    : {
                        ...Current,
                        InlineLimitBytes: Number(Event.currentTarget.value) as InlineTextLimitBytes,
                      },
                )
              }
              value={String(Value.InlineLimitBytes)}
            >
              {InlineOptions.filter((Bytes) => Bytes >= Value.EditLimitBytes).map((Bytes) => (
                <option key={Bytes} value={Bytes}>
                  {Bytes / MiB} MiB
                </option>
              ))}
            </Select>
          </label>
          <Button appearance="primary" disabled={Saving} type="submit">
            {Saving ? "Saving…" : "Save text limits"}
          </Button>
        </form>
      )}
    </section>
  );
}
