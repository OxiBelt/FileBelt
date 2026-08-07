// SPDX-License-Identifier: Apache-2.0

import { Checkbox } from "@fluentui/react-components";
import { AlertTriangle, File, Folder, LockKeyhole, Share2 } from "lucide-react";
import type { KeyboardEvent, MouseEvent, ReactNode } from "react";

import { BidiText, FileBeltIcon, StatusPill } from "@filebelt/design-system";

import type { FileEntry } from "./model.js";
import type { SelectionAction, SelectionState } from "./selection.js";
import type { Strings } from "./strings.js";

export interface FileTableProps {
  dispatchSelection(Action: SelectionAction): void;
  Entries: readonly FileEntry[];
  onOpenActions(Entry: FileEntry, Anchor: HTMLElement): void;
  Selection: SelectionState;
  Strings: Strings;
}

function FormatBytes(Value: number | null): string {
  if (Value === null) return "—";
  return new Intl.NumberFormat(undefined, {
    maximumFractionDigits: 1,
    notation: "compact",
    style: "unit",
    unit: "byte",
    unitDisplay: "narrow",
  }).format(Value);
}

function FormatDate(Value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(Value));
}

export function FileTable({
  dispatchSelection: DispatchSelection,
  Entries,
  onOpenActions: OnOpenActions,
  Selection,
  Strings,
}: FileTableProps): ReactNode {
  const OrderedIds = Entries.map(({ Id }) => Id);

  const FocusRow = (Id: string): void => {
    DispatchSelection({ Id, Type: "focus" });
    requestAnimationFrame(() => document.getElementById(`file-row-${Id}`)?.focus());
  };

  const OnRowKeyDown = (Event: KeyboardEvent<HTMLTableRowElement>, Entry: FileEntry, Index: number): void => {
    if ((Event.ctrlKey || Event.metaKey) && Event.key.toLowerCase() === "a") {
      Event.preventDefault();
      DispatchSelection({ OrderedIds, Type: "all" });
      return;
    }
    if (Event.key === " " || Event.key === "Spacebar") {
      Event.preventDefault();
      DispatchSelection({ Id: Entry.Id, Type: Event.shiftKey ? "range" : "toggle", ...(Event.shiftKey ? { OrderedIds } : {}) } as SelectionAction);
      return;
    }
    if (Event.key === "ArrowDown" || Event.key === "ArrowUp") {
      Event.preventDefault();
      const Offset = Event.key === "ArrowDown" ? 1 : -1;
      const Target = Entries[Math.max(0, Math.min(Entries.length - 1, Index + Offset))];
      if (Target !== undefined) {
        if (Event.shiftKey) DispatchSelection({ Id: Target.Id, OrderedIds, Type: "range" });
        FocusRow(Target.Id);
      }
      return;
    }
    if (Event.shiftKey && Event.key === "F10") {
      Event.preventDefault();
      OnOpenActions(Entry, Event.currentTarget);
    }
  };

  const OnRowClick = (Event: MouseEvent<HTMLTableRowElement>, Entry: FileEntry): void => {
    if (Event.shiftKey) DispatchSelection({ Id: Entry.Id, OrderedIds, Type: "range" });
    else if (Event.ctrlKey || Event.metaKey) DispatchSelection({ Id: Entry.Id, Type: "toggle" });
    else DispatchSelection({ Id: Entry.Id, Type: "replace" });
  };

  if (Entries.length === 0) {
    return <div className="fb-empty"><Folder aria-hidden="true" size={40} strokeWidth={1.5} /><p>{Strings.noFiles}</p></div>;
  }

  return (
    <div className="fb-table-scroll">
      <table aria-label={Strings.files} aria-multiselectable="true" className="fb-file-table" role="grid">
        <thead>
          <tr role="row">
            <th aria-label={Strings.selected} className="fb-select-column" role="columnheader" />
            <th role="columnheader">{Strings.name}</th>
            <th role="columnheader">{Strings.owner}</th>
            <th role="columnheader">{Strings.modified}</th>
            <th role="columnheader">{Strings.size}</th>
            <th role="columnheader">{Strings.status}</th>
          </tr>
        </thead>
        <tbody>
          {Entries.map((Entry, Index) => {
            const Selected = Selection.SelectedIds.has(Entry.Id);
            const Focused = Selection.FocusedId === Entry.Id || (Selection.FocusedId === null && Index === 0);
            return (
              <tr
                aria-selected={Selected}
                className={Selected ? "fb-file-row is-selected" : "fb-file-row"}
                id={`file-row-${Entry.Id}`}
                key={Entry.Id}
                onClick={(Event) => OnRowClick(Event, Entry)}
                onContextMenu={(Event) => {
                  Event.preventDefault();
                  if (!Selected) DispatchSelection({ Id: Entry.Id, Type: "replace" });
                  OnOpenActions(Entry, Event.currentTarget);
                }}
                onFocus={() => DispatchSelection({ Id: Entry.Id, Type: "focus" })}
                onKeyDown={(Event) => OnRowKeyDown(Event, Entry, Index)}
                role="row"
                tabIndex={Focused ? 0 : -1}
              >
                <td className="fb-select-column" role="gridcell">
                  <Checkbox
                    aria-label={Selected ? Strings.deselectItem(Entry.Name) : Strings.selectItem(Entry.Name)}
                    checked={Selected}
                    onChange={() => DispatchSelection({ Id: Entry.Id, Type: "toggle" })}
                    onClick={(Event) => Event.stopPropagation()}
                  />
                </td>
                <td role="gridcell">
                  <span className="fb-name-cell">
                    <FileBeltIcon Icon={Entry.Kind === "folder" ? Folder : File} />
                    <BidiText>{Entry.Name}</BidiText>
                    {Entry.Shared ? <FileBeltIcon Icon={Share2} size={16} /> : null}
                  </span>
                </td>
                <td role="gridcell"><BidiText>{Entry.Owner}</BidiText></td>
                <td role="gridcell"><time dateTime={Entry.ModifiedAt}>{FormatDate(Entry.ModifiedAt)}</time></td>
                <td role="gridcell">{FormatBytes(Entry.Size)}</td>
                <td role="gridcell">
                  {Entry.Status === "conflict" ? <StatusPill Kind="warning"><FileBeltIcon Icon={AlertTriangle} size={16} /> {Strings.conflict}</StatusPill> : null}
                  {Entry.Status === "quarantined" ? <StatusPill Kind="danger"><FileBeltIcon Icon={LockKeyhole} size={16} /> {Strings.quarantined}</StatusPill> : null}
                  {Entry.Status === "ready" ? <StatusPill Kind="success">{Strings.ready}</StatusPill> : null}
                  {Entry.Status === "uploading" ? <StatusPill Kind="informative">{Strings.uploading}</StatusPill> : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
