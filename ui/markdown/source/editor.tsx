// SPDX-License-Identifier: Apache-2.0

import { defaultKeymap } from "@codemirror/commands";
import { markdown } from "@codemirror/lang-markdown";
import { Compartment, EditorState } from "@codemirror/state";
import { EditorView, keymap } from "@codemirror/view";
import { Awareness } from "y-protocols/awareness";
import { yCollab, yUndoManagerKeymap } from "y-codemirror.next";
import * as Y from "yjs";
import { useEffect, useRef, type JSX } from "react";
import type { CollaborationIdentity, MarkdownSource } from "./types.js";

export interface MarkdownCollaboration {
  Awareness: Awareness;
  Document: Y.Doc;
  TextName: string;
}

export interface MarkdownSourceEditorProps {
  Collaboration?: MarkdownCollaboration;
  Disabled?: boolean;
  Identity?: CollaborationIdentity;
  OnTextChange?: (Text: string) => void;
  OnSelectionChange?: (Selection: { End: number; Start: number }) => void;
  Source: MarkdownSource;
  SourceEditorLabel: string;
}

export function MarkdownSourceEditor({ Collaboration, Disabled = false, Identity, OnSelectionChange, OnTextChange, Source, SourceEditorLabel }: MarkdownSourceEditorProps): JSX.Element {
  const Host = useRef<HTMLDivElement>(null);
  const ViewReference = useRef<EditorView | null>(null);
  const ActiveCollaborationReference = useRef<MarkdownCollaboration | null>(null);
  const DisabledCompartment = useRef(new Compartment());
  const LabelCompartment = useRef(new Compartment());
  const InitialSource = useRef(Source.Text);
  const OnTextChangeReference = useRef(OnTextChange);
  const OnSelectionChangeReference = useRef(OnSelectionChange);
  OnTextChangeReference.current = OnTextChange;
  OnSelectionChangeReference.current = OnSelectionChange;

  useEffect(() => {
    if (Host.current === null) return;
    const LocalDocument = new Y.Doc();
    const ActiveCollaboration = Collaboration ?? { Awareness: new Awareness(LocalDocument), Document: LocalDocument, TextName: "markdown" };
    const OwnsDocument = Collaboration === undefined;
    const SharedText = ActiveCollaboration.Document.getText(ActiveCollaboration.TextName);
    if (OwnsDocument && SharedText.length === 0 && InitialSource.current.length > 0) SharedText.insert(0, InitialSource.current);
    const View = new EditorView({
      parent: Host.current,
      state: EditorState.create({
        doc: SharedText.toString(),
        extensions: [
          keymap.of([...yUndoManagerKeymap, ...defaultKeymap]),
          EditorView.lineWrapping,
          markdown(),
          DisabledCompartment.current.of(EditorView.editable.of(!Disabled)),
          LabelCompartment.current.of(EditorView.contentAttributes.of({ "aria-label": SourceEditorLabel, "aria-multiline": "true" })),
          yCollab(SharedText, ActiveCollaboration.Awareness, { undoManager: new Y.UndoManager(SharedText) }),
          EditorView.updateListener.of((Update) => {
            if (Update.docChanged) OnTextChangeReference.current?.(Update.state.doc.toString());
            if (Update.selectionSet) {
              const Selection = Update.state.selection.main;
              OnSelectionChangeReference.current?.({ End: Selection.to, Start: Selection.from });
            }
          }),
        ],
      }),
    });
    ViewReference.current = View;
    ActiveCollaborationReference.current = ActiveCollaboration;
    return () => {
      ViewReference.current = null;
      ActiveCollaborationReference.current = null;
      if (OwnsDocument) ActiveCollaboration.Awareness.destroy();
      View.destroy();
      if (OwnsDocument) LocalDocument.destroy();
    };
  }, [Collaboration]);

  useEffect(() => {
    const View = ViewReference.current;
    if (View !== null) View.dispatch({ effects: DisabledCompartment.current.reconfigure(EditorView.editable.of(!Disabled)) });
  }, [Disabled]);

  useEffect(() => {
    const View = ViewReference.current;
    if (View !== null) View.dispatch({ effects: LabelCompartment.current.reconfigure(EditorView.contentAttributes.of({ "aria-label": SourceEditorLabel, "aria-multiline": "true" })) });
  }, [SourceEditorLabel]);

  useEffect(() => {
    const View = ViewReference.current;
    if (View !== null && View.state.doc.toString() !== Source.Text) {
      View.dispatch({ changes: { from: 0, insert: Source.Text, to: View.state.doc.length } });
    }
  }, [Source.Text]);

  useEffect(() => {
    const AwarenessValue = ActiveCollaborationReference.current?.Awareness;
    if (AwarenessValue === undefined) return;
    AwarenessValue.setLocalStateField("filebelt", Identity ?? null);
    AwarenessValue.setLocalStateField("user", Identity === undefined ? null : { color: Identity.Color, name: Identity.DisplayName });
  }, [Identity]);

  return <div data-filebelt-markdown-editor="source" ref={Host} />;
}
