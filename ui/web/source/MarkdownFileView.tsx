// SPDX-License-Identifier: Apache-2.0

import { Button, Dialog, DialogActions, DialogBody, DialogContent, DialogSurface, DialogTitle, Spinner } from "@fluentui/react-components";
import { ArrowLeft, Save as SaveIcon } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { DecodeEditableText, DecodeViewableText, EncodeText, EnglishMarkdownStrings, MaximumEditableBytes, MarkdownRealtimeSession, MarkdownSurface, MergeMarkdownSources, TextSurface, type FileBeltReference, type MarkdownCollaborationState, type MarkdownMode, type MarkdownSource } from "@filebelt/markdown";
import type { FileBeltClient } from "./client.js";
import { VersionConflictError } from "./client.js";
import type { FileEntry } from "./model.js";
import { En } from "./strings.js";
import { MarkdownMcpProposals } from "./MarkdownMcpProposals.js";
import type { NavigationGuard } from "./App.js";
import type { McpSettingsClient } from "@filebelt/mcp-settings";

interface MarkdownFileViewProps {
  Client: FileBeltClient;
  Entry: FileEntry;
  McpClient?: McpSettingsClient;
  OnClose(): void;
  OnFileBeltLink(Target: FileBeltReference): boolean;
  OnNavigationGuardChange(Guard: NavigationGuard | undefined): void;
  OnSaved(): void;
}

export function MarkdownFileView({ Client, Entry, McpClient, OnClose, OnFileBeltLink, OnNavigationGuardChange, OnSaved }: MarkdownFileViewProps): ReactNode {
  const [Source, SetSource] = useState<MarkdownSource | null>(null);
  const [Mode, SetMode] = useState<MarkdownMode>("split");
  const [ExpectedHeadVersionId, SetExpectedHeadVersionId] = useState(Entry.HeadVersionId);
  const [ErrorMessage, SetError] = useState<string | null>(null);
  const [Saving, SetSaving] = useState(false);
  const [Dirty, SetDirty] = useState(false);
  const [SavedText, SetSavedText] = useState("");
  const [Collaboration, SetCollaboration] = useState<MarkdownRealtimeSession | null>(null);
  const [CollaborationState, SetCollaborationState] = useState<MarkdownCollaborationState | "fallback">(Entry.TextEligibility === "editable" ? "connecting" : "fallback");
  const [ConflictCopyAvailable, SetConflictCopyAvailable] = useState(false);
  const [Selection, SetSelection] = useState({ End: 0, Start: 0 });
  const [LeaveDialogOpen, SetLeaveDialogOpen] = useState(false);
  const [TextLimits, SetTextLimits] = useState({ Edit: 2 * 1024 * 1024, Inline: 8 * 1024 * 1024 });
  const [InvalidText, SetInvalidText] = useState(false);
  const [ReconnectPending, SetReconnectPending] = useState(false);
  const PendingNavigation = useRef<(() => void) | undefined>(undefined);
  const ReconnectPendingRef = useRef(false);
  const Mounted = useRef(true);
  const IsMarkdown = Entry.MediaType === "text/markdown";
  const CanInline = Entry.Size === null || Entry.Size <= TextLimits.Inline;
  const CanEdit = Entry.TextEligibility === "editable" && (Entry.Size === null || Entry.Size <= TextLimits.Edit);
  useEffect(() => {
    Mounted.current = true;
    return () => {
      Mounted.current = false;
      ReconnectPendingRef.current = false;
    };
  }, []);
  useEffect(() => {
    let Active = true;
    void Client.getTextPreferences().then(({ Value }) => {
      if (Active) SetTextLimits({ Edit: Value.EditLimitBytes, Inline: Value.InlineLimitBytes });
    }).catch(() => undefined);
    return () => { Active = false; };
  }, [Client]);
  useEffect(() => {
    if (Entry.HeadVersionId === null) return;
    let Active = true;
    let Session: MarkdownRealtimeSession | undefined;
    SetCollaboration(null);
    SetCollaborationState(CanEdit ? "connecting" : "fallback");
    void Client.readMarkdown(Entry.Id, Entry.HeadVersionId).then(async (Contents) => {
      const Bytes = new Uint8Array(await Contents.arrayBuffer());
      const Decoded = CanEdit ? DecodeEditableText(Bytes) : DecodeViewableText(Bytes);
      if (!Active) return;
      SetSource(Decoded);
      SetSavedText(Decoded.Text);
      SetDirty(false);
      SetConflictCopyAvailable(false);
      if (!CanEdit) return;
      const ClientId = crypto.randomUUID();
      const Grant = await Client.beginMarkdownCollaboration(Entry.Id, ClientId);
      if (!Active) return;
      if (Grant === null) {
        SetCollaborationState("fallback");
        return;
      }
      Session = await MarkdownRealtimeSession.Connect({ Grant, OnStateChange: SetCollaborationState });
      if (!Active) {
        Session.Destroy();
        return;
      }
      SetSource({ ...Decoded, Text: Session.CurrentText() });
      SetDirty(Session.CurrentText() !== Decoded.Text);
      SetCollaboration(Session);
    }).catch((Cause: unknown) => {
      if (Active) {
        SetCollaborationState("disconnected");
        SetInvalidText(true);
        SetError(Cause instanceof Error ? Cause.message : En.markdownUnavailable);
      }
    });
    return () => {
      Active = false;
      Session?.Destroy();
    };
  }, [CanEdit, Client, Entry.HeadVersionId, Entry.Id, Entry.TextEligibility]);

  const Reconnect = async (): Promise<void> => {
    if (ReconnectPendingRef.current || Source === null || ExpectedHeadVersionId === null) return;
    ReconnectPendingRef.current = true;
    SetReconnectPending(true);
    const LocalText = Collaboration?.CurrentText() ?? Source.Text;
    let FallbackRemote = { ...Source, Text: SavedText };
    let FallbackVersionId = ExpectedHeadVersionId;
    Collaboration?.Destroy();
    SetCollaboration(null);
    SetCollaborationState("connecting");
    SetError(null);
    try {
      const Latest = await Client.readMarkdownHead(Entry.Id);
      const Remote = DecodeEditableText(new Uint8Array(await Latest.Contents.arrayBuffer()));
      FallbackRemote = Remote;
      FallbackVersionId = Latest.VersionId;
      const ClientId = crypto.randomUUID();
      const Grant = await Client.beginMarkdownCollaboration(Entry.Id, ClientId);
      if (Grant === null) {
        ApplyFallbackMerge(LocalText, Remote, Latest.VersionId);
        return;
      }
      const Session = await MarkdownRealtimeSession.Connect({ Grant, OnStateChange: SetCollaborationState });
      const LiveText = Session.CurrentText();
      const Merged = MergeMarkdownSources(SavedText, LocalText, LiveText);
      if (Merged.Conflict) {
        Session.Destroy();
        ApplyFallbackMerge(LocalText, { ...Remote, Text: LiveText }, Latest.VersionId, false);
        return;
      }
      if (Merged.Text !== LiveText) Session.ApplyReconnectMerge(Merged.Text);
      SetSource({ ...Remote, Text: Merged.Text });
      SetExpectedHeadVersionId(Latest.VersionId);
      SetSavedText(LiveText);
      SetDirty(Merged.Text !== LiveText);
      SetCollaboration(Session);
    } catch (Cause) {
      ApplyFallbackMerge(LocalText, FallbackRemote, FallbackVersionId);
      SetError(Cause instanceof Error ? Cause.message : En.markdownUnavailable);
    } finally {
      ReconnectPendingRef.current = false;
      if (Mounted.current) SetReconnectPending(false);
    }
  };

  const ApplyFallbackMerge = (LocalText: string, Remote: MarkdownSource, VersionId: string, RemoteIsHead = true): void => {
    const Merged = MergeMarkdownSources(SavedText, LocalText, Remote.Text);
    const NewBase = RemoteIsHead ? Remote.Text : SavedText;
    SetExpectedHeadVersionId(VersionId);
    SetSavedText(NewBase);
    SetSource({ ...Remote, Text: Merged.Text });
    SetDirty(Merged.Text !== NewBase);
    SetConflictCopyAvailable(Merged.Conflict);
    SetCollaborationState("fallback");
    SetError(Merged.Conflict ? En.markdownConflictReview : En.markdownConflictMerged);
  };

  const SaveMarkdown = async (): Promise<void> => {
    if (Source === null || ExpectedHeadVersionId === null) return;
    SetSaving(true);
    SetError(null);
    try {
      const CurrentSource = Collaboration === null ? Source : { ...Source, Text: Collaboration.CurrentText() };
      const CheckpointId = Collaboration === null ? undefined : await Collaboration.RequestCheckpoint();
      const Encoded = EncodeText(CurrentSource, TextLimits.Edit);
      const Contents = new Blob([Encoded.buffer as ArrayBuffer], { type: Entry.MediaType ?? "text/plain" });
      const VersionId = await Client.saveMarkdown({
        ...(CheckpointId === undefined ? {} : { CheckpointId }),
        Contents,
        EntryId: Entry.Id,
        ExpectedHeadVersionId,
        Name: Entry.Name,
      });
      SetExpectedHeadVersionId(VersionId);
      SetSavedText(CurrentSource.Text);
      SetDirty(false);
      OnSaved();
    } catch (Cause) {
      if (Cause instanceof VersionConflictError) {
        try {
          const LocalText = Collaboration?.CurrentText() ?? Source.Text;
          const Latest = await Client.readMarkdownHead(Entry.Id);
          const Remote = DecodeEditableText(new Uint8Array(await Latest.Contents.arrayBuffer()));
          const Merged = MergeMarkdownSources(SavedText, LocalText, Remote.Text);
          Collaboration?.Destroy();
          SetCollaboration(null);
          SetCollaborationState("fallback");
          SetExpectedHeadVersionId(Latest.VersionId);
          SetSavedText(Remote.Text);
          SetSource({ ...Remote, Text: Merged.Text });
          SetDirty(Merged.Text !== Remote.Text);
          SetConflictCopyAvailable(true);
          SetError(Merged.Conflict ? En.markdownConflictReview : En.markdownConflictMerged);
        } catch {
          SetConflictCopyAvailable(true);
          SetError(En.markdownConflict);
        }
      } else {
        SetError(Cause instanceof Error ? Cause.message : En.markdownSaveFailed);
      }
    } finally {
      SetSaving(false);
    }
  };

  const SaveConflictCopy = async (): Promise<void> => {
    if (Source === null) return;
    SetSaving(true);
    SetError(null);
    try {
      const CurrentSource = Collaboration === null ? Source : { ...Source, Text: Collaboration.CurrentText() };
      const Encoded = EncodeText(CurrentSource, TextLimits.Edit);
      await Client.saveMarkdownCopy({
        Contents: new Blob([Encoded.buffer as ArrayBuffer], { type: Entry.MediaType ?? "text/plain" }),
        EntryId: Entry.Id,
        Name: ConflictCopyName(Entry.Name),
      });
      SetConflictCopyAvailable(false);
      SetError(En.markdownConflictCopySaved);
      OnSaved();
    } catch (Cause) {
      SetError(Cause instanceof Error ? Cause.message : En.markdownSaveFailed);
    } finally {
      SetSaving(false);
    }
  };

  const ApplyProposal = (Proposal: string, BaseText: string, InvocationId: string): boolean => {
    const CurrentText = Collaboration?.CurrentText() ?? Source?.Text;
    if (CurrentText !== BaseText) return false;
    if (Collaboration !== null) {
      Collaboration.ApplyMcpProposal(Proposal, InvocationId);
    } else {
      SetSource((Current) => Current === null ? Current : { ...Current, Text: Proposal });
      SetDirty(Proposal !== SavedText);
    }
    return true;
  };

  const ExportLocal = (): void => {
    if (Source === null) return;
    const CurrentSource = Collaboration === null ? Source : { ...Source, Text: Collaboration.CurrentText() };
    const Url = URL.createObjectURL(new Blob([EncodeText(CurrentSource, MaximumEditableBytes).buffer as ArrayBuffer], { type: "text/plain" }));
    const Anchor = document.createElement("a");
    Anchor.download = `${Entry.Name}.local.md`;
    Anchor.href = Url;
    Anchor.click();
    URL.revokeObjectURL(Url);
  };

  const RequestLeave = useCallback((Continue: () => void): void => {
    if (!Dirty) {
      Continue();
      return;
    }
    PendingNavigation.current = Continue;
    SetLeaveDialogOpen(true);
  }, [Dirty]);

  const Stay = (): void => {
    PendingNavigation.current = undefined;
    SetLeaveDialogOpen(false);
  };

  const Leave = (): void => {
    const Continue = PendingNavigation.current;
    PendingNavigation.current = undefined;
    SetLeaveDialogOpen(false);
    Collaboration?.Destroy();
    Continue?.();
  };

  useEffect(() => {
    OnNavigationGuardChange(RequestLeave);
    return () => OnNavigationGuardChange(undefined);
  }, [OnNavigationGuardChange, RequestLeave]);

  useEffect(() => {
    return () => Collaboration?.Destroy();
  }, [Collaboration]);

  useEffect(() => {
    const OnBeforeUnload = (Event: BeforeUnloadEvent): void => {
      if (!Dirty) return;
      Event.preventDefault();
      Event.returnValue = "";
    };
    window.addEventListener("beforeunload", OnBeforeUnload);
    return () => window.removeEventListener("beforeunload", OnBeforeUnload);
  }, [Dirty]);

  if (Entry.HeadVersionId === null || Entry.TextEligibility === "ineligible" || Entry.TextEligibility === "history-only" || !CanInline) return <div className="fb-error" role="alert">{!CanInline ? En.textInlineLimitReached : En.markdownUnavailable}</div>;
  if (Source === null) return <div className="fb-loading"><Spinner label={En.markdownLoading} /></div>;
  const EditingDisabled = !CanEdit || CollaborationState === "connecting" || CollaborationState === "disconnected";
  return <section aria-labelledby="markdown-heading" className="fb-markdown-view">
    <header className="fb-page-heading"><div><p className="fb-eyebrow">{En.file}</p><h1 id="markdown-heading">{Entry.Name}</h1></div><div className="fb-heading-actions"><Button icon={<ArrowLeft />} onClick={OnClose}>{En.backToFiles}</Button>{Entry.TextEligibility === "editable" ? <Button appearance="primary" disabled={Saving || !Dirty || EditingDisabled} icon={<SaveIcon />} onClick={() => void SaveMarkdown()}>{En.save}</Button> : null}</div></header>
    {Entry.TextEligibility === "editable" && CollaborationState !== "fallback" ? <p aria-live="polite" className="fb-muted">{CollaborationState === "connected" ? En.markdownCollaborationConnected : CollaborationState === "connecting" ? En.markdownCollaborationConnecting : En.markdownCollaborationDisconnected}</p> : null}
    {CollaborationState === "disconnected" || ReconnectPending ? <div className="fb-heading-actions"><Button onClick={ExportLocal}>{En.markdownExportLocal}</Button><Button disabled={ReconnectPending} onClick={() => void Reconnect()}>{En.markdownReconnect}</Button></div> : null}
    {ErrorMessage === null ? null : <div className="fb-error" role="alert">{ErrorMessage}</div>}
    {InvalidText ? <div className="fb-heading-actions"><p>{En.textInvalidGuide}</p><Button onClick={() => void Client.setNodeContentClass(Entry.Id, "binary")}>{En.textMarkBinary}</Button></div> : null}
    {ConflictCopyAvailable ? <div><Button disabled={Saving} onClick={() => void SaveConflictCopy()}>{En.markdownSaveConflictCopy}</Button></div> : null}
    {IsMarkdown ? <MarkdownSurface {...(Collaboration === null ? {} : { Collaboration })} Disabled={EditingDisabled} Mode={Mode} OnFileBeltLink={(Target) => { if (!OnFileBeltLink(Target)) SetError(En.markdownReferenceUnavailable); }} OnModeChange={SetMode} OnSelectionChange={SetSelection} OnTextChange={(Text) => { SetDirty(Text !== SavedText); SetSource((Current) => Current === null ? Current : { ...Current, Text }); }} Source={Source} Strings={EnglishMarkdownStrings} /> : <TextSurface {...(Collaboration === null ? {} : { Collaboration })} Disabled={EditingDisabled} OnSelectionChange={SetSelection} OnTextChange={(Text) => { SetDirty(Text !== SavedText); SetSource((Current) => Current === null ? Current : { ...Current, Text }); }} Source={Source} Strings={{ Edit: "Edit source", SourceEditor: "Text source", View: "View source" }} />}
    {McpClient === undefined || !IsMarkdown || !CanEdit || ExpectedHeadVersionId === null ? null : <MarkdownMcpProposals BaseVersionId={ExpectedHeadVersionId} Client={McpClient} NodeId={Entry.Id} OnApply={ApplyProposal} Selection={Selection} Source={Collaboration?.CurrentText() ?? Source.Text} />}
    <Dialog modalType="modal" onOpenChange={(Event, Data) => { void Event; if (!Data.open) Stay(); }} open={LeaveDialogOpen}>
      <DialogSurface aria-describedby="markdown-leave-description">
        <DialogBody>
          <DialogTitle>{En.markdownLeaveHeading}</DialogTitle>
          <DialogContent id="markdown-leave-description">{En.markdownLeaveDescription}</DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={Stay}>{En.markdownStay}</Button>
            <Button onClick={() => { ExportLocal(); Leave(); }}>{En.markdownExportLocal}</Button>
            <Button appearance="primary" onClick={Leave}>{En.markdownDiscardChanges}</Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  </section>;
}

function ConflictCopyName(Name: string): string {
  const Match = /^(.*?)(\.[^.]+)?$/.exec(Name);
  return `${Match?.[1] ?? Name} (conflict copy)${Match?.[2] ?? ".md"}`;
}
