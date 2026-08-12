// SPDX-License-Identifier: Apache-2.0

import { useDeferredValue, useId, useMemo, type JSX, type KeyboardEvent } from "react";
import { TextSourceEditor, type TextCollaboration } from "./editor.js";
import { ParseFileBeltGfmV1 } from "./parser.js";
import { MarkdownPreview } from "./renderer.js";
import type { CollaborationIdentity, MarkdownMode, MarkdownSource, MarkdownStrings, TextSource, TextStrings } from "./types.js";

export interface TextSurfaceProps {
  Collaboration?: TextCollaboration;
  Disabled?: boolean;
  Identity?: CollaborationIdentity;
  OnSelectionChange?: (Selection: { End: number; Start: number }) => void;
  OnTextChange?: (Text: string) => void;
  Source: TextSource;
  Strings: TextStrings;
}

/** Accessible language-neutral source editor/viewer for validated text. */
export function TextSurface({ Collaboration, Disabled, Identity, OnSelectionChange, OnTextChange, Source, Strings }: TextSurfaceProps): JSX.Element {
  return <section data-filebelt-text-mode={Disabled === true ? "view" : "edit"}>
    <div aria-label={Disabled === true ? Strings.View : Strings.Edit}>
      <TextSourceEditor {...(Collaboration === undefined ? {} : { Collaboration })} {...(Disabled === undefined ? {} : { Disabled })} {...(Identity === undefined ? {} : { Identity })} {...(OnSelectionChange === undefined ? {} : { OnSelectionChange })} {...(OnTextChange === undefined ? {} : { OnTextChange })} Source={Source} SourceEditorLabel={Strings.SourceEditor} />
    </div>
  </section>;
}

export interface MarkdownSurfaceProps {
  Collaboration?: TextCollaboration;
  Disabled?: boolean;
  Identity?: CollaborationIdentity;
  Mode: MarkdownMode;
  OnFileBeltLink?: Parameters<typeof MarkdownPreview>[0]["OnFileBeltLink"];
  OnModeChange: (Mode: MarkdownMode) => void;
  OnSelectionChange?: (Selection: { End: number; Start: number }) => void;
  OnTextChange?: (Text: string) => void;
  Source: MarkdownSource;
  Strings: MarkdownStrings;
}

export function MarkdownSurface({ Collaboration, Disabled, Identity, Mode, OnFileBeltLink, OnModeChange, OnSelectionChange, OnTextChange, Source, Strings }: MarkdownSurfaceProps): JSX.Element {
  // Parsing and preview delivery are non-urgent; keep CodeMirror input responsive.
  const PreviewSource = useDeferredValue(Source);
  const Parsed = useMemo(() => ParseFileBeltGfmV1(PreviewSource), [PreviewSource]);
  const SurfaceId = useId().replaceAll(":", "-");
  const SourcePanelId = `${SurfaceId}-source`;
  const PreviewPanelId = `${SurfaceId}-preview`;
  const ShowSource = Mode === "source" || Mode === "split";
  const ShowPreview = Mode === "preview" || Mode === "split";
  return <section data-filebelt-markdown-mode={Mode}>
    <div aria-label="Markdown mode" role="tablist">
      <ModeButton Active={Mode === "source"} Controls={SourcePanelId} Label={Strings.Edit} Mode="source" OnModeChange={OnModeChange} />
      <ModeButton Active={Mode === "split"} Controls={`${SourcePanelId} ${PreviewPanelId}`} Label={Strings.Split} Mode="split" OnModeChange={OnModeChange} />
      <ModeButton Active={Mode === "preview"} Controls={PreviewPanelId} Label={Strings.Preview} Mode="preview" OnModeChange={OnModeChange} />
    </div>
    <div aria-label={Strings.Edit} hidden={!ShowSource} id={SourcePanelId} role="tabpanel"><TextSourceEditor {...(Collaboration === undefined ? {} : { Collaboration })} {...(Disabled === undefined ? {} : { Disabled })} {...(Identity === undefined ? {} : { Identity })} {...(OnSelectionChange === undefined ? {} : { OnSelectionChange })} {...(OnTextChange === undefined ? {} : { OnTextChange })} Source={Source} SourceEditorLabel={Strings.SourceEditor} /></div>
    <div aria-label={Strings.Preview} hidden={!ShowPreview} id={PreviewPanelId} role="tabpanel"><MarkdownPreview Ast={Parsed.Ast} {...(OnFileBeltLink === undefined ? {} : { OnFileBeltLink })} /></div>
  </section>;
}

function ModeButton({ Active, Controls, Label, Mode, OnModeChange }: { Active: boolean; Controls: string; Label: string; Mode: MarkdownMode; OnModeChange: (Mode: MarkdownMode) => void }): JSX.Element {
  const OnKeyDown = (Event: KeyboardEvent<HTMLButtonElement>): void => {
    if (!MatchesTabNavigationKey(Event.key)) return;
    const Tabs = [...(Event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>("[role=tab]") ?? [])];
    const Current = Tabs.indexOf(Event.currentTarget);
    const Next = Event.key === "Home" ? 0 : Event.key === "End" ? Tabs.length - 1 : (Current + (Event.key === "ArrowLeft" ? -1 : 1) + Tabs.length) % Tabs.length;
    Event.preventDefault();
    Tabs[Next]?.focus();
    Tabs[Next]?.click();
  };
  return <button aria-controls={Controls} aria-selected={Active} onClick={() => OnModeChange(Mode)} onKeyDown={OnKeyDown} role="tab" tabIndex={Active ? 0 : -1} type="button">{Label}</button>;
}

function MatchesTabNavigationKey(Key: string): boolean {
  return Key === "ArrowLeft" || Key === "ArrowRight" || Key === "Home" || Key === "End";
}
