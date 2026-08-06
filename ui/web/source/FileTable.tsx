// SPDX-License-Identifier: Apache-2.0

import { Checkbox } from "@fluentui/react-components";
import { AlertTriangle, File, Folder, LockKeyhole, Share2 } from "lucide-react";
import type { KeyboardEvent, MouseEvent, ReactNode } from "react";

import { BidiText, FileBeltIcon, StatusPill } from "@filebelt/design-system";

import type { FileEntry } from "./model.js";
import type { SelectionAction, SelectionState } from "./selection.js";
import type { Strings } from "./strings.js";

export interface FileTableProps {
  dispatchSelection(action: SelectionAction): void;
  entries: readonly FileEntry[];
  onOpenActions(entry: FileEntry, anchor: HTMLElement): void;
  selection: SelectionState;
  strings: Strings;
}

function formatBytes(value: number | null): string {
  if (value === null) return "—";
  return new Intl.NumberFormat(undefined, {
    maximumFractionDigits: 1,
    notation: "compact",
    style: "unit",
    unit: "byte",
    unitDisplay: "narrow",
  }).format(value);
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export function FileTable({
  dispatchSelection,
  entries,
  onOpenActions,
  selection,
  strings,
}: FileTableProps): ReactNode {
  const orderedIds = entries.map(({ id }) => id);

  const focusRow = (id: string): void => {
    dispatchSelection({ id, type: "focus" });
    requestAnimationFrame(() => document.getElementById(`file-row-${id}`)?.focus());
  };

  const onRowKeyDown = (event: KeyboardEvent<HTMLTableRowElement>, entry: FileEntry, index: number): void => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "a") {
      event.preventDefault();
      dispatchSelection({ orderedIds, type: "all" });
      return;
    }
    if (event.key === " " || event.key === "Spacebar") {
      event.preventDefault();
      dispatchSelection({ id: entry.id, type: event.shiftKey ? "range" : "toggle", ...(event.shiftKey ? { orderedIds } : {}) } as SelectionAction);
      return;
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const offset = event.key === "ArrowDown" ? 1 : -1;
      const target = entries[Math.max(0, Math.min(entries.length - 1, index + offset))];
      if (target !== undefined) {
        if (event.shiftKey) dispatchSelection({ id: target.id, orderedIds, type: "range" });
        focusRow(target.id);
      }
      return;
    }
    if (event.shiftKey && event.key === "F10") {
      event.preventDefault();
      onOpenActions(entry, event.currentTarget);
    }
  };

  const onRowClick = (event: MouseEvent<HTMLTableRowElement>, entry: FileEntry): void => {
    if (event.shiftKey) dispatchSelection({ id: entry.id, orderedIds, type: "range" });
    else if (event.ctrlKey || event.metaKey) dispatchSelection({ id: entry.id, type: "toggle" });
    else dispatchSelection({ id: entry.id, type: "replace" });
  };

  if (entries.length === 0) {
    return <div className="fb-empty"><Folder aria-hidden="true" size={40} strokeWidth={1.5} /><p>{strings.noFiles}</p></div>;
  }

  return (
    <div className="fb-table-scroll">
      <table aria-label={strings.files} aria-multiselectable="true" className="fb-file-table" role="grid">
        <thead>
          <tr role="row">
            <th aria-label={strings.selected} className="fb-select-column" role="columnheader" />
            <th role="columnheader">{strings.name}</th>
            <th role="columnheader">{strings.owner}</th>
            <th role="columnheader">{strings.modified}</th>
            <th role="columnheader">{strings.size}</th>
            <th role="columnheader">{strings.status}</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry, index) => {
            const selected = selection.selectedIds.has(entry.id);
            const focused = selection.focusedId === entry.id || (selection.focusedId === null && index === 0);
            return (
              <tr
                aria-selected={selected}
                className={selected ? "fb-file-row is-selected" : "fb-file-row"}
                id={`file-row-${entry.id}`}
                key={entry.id}
                onClick={(event) => onRowClick(event, entry)}
                onContextMenu={(event) => {
                  event.preventDefault();
                  if (!selected) dispatchSelection({ id: entry.id, type: "replace" });
                  onOpenActions(entry, event.currentTarget);
                }}
                onFocus={() => dispatchSelection({ id: entry.id, type: "focus" })}
                onKeyDown={(event) => onRowKeyDown(event, entry, index)}
                role="row"
                tabIndex={focused ? 0 : -1}
              >
                <td className="fb-select-column" role="gridcell">
                  <Checkbox
                    aria-label={selected ? strings.deselectItem(entry.name) : strings.selectItem(entry.name)}
                    checked={selected}
                    onChange={() => dispatchSelection({ id: entry.id, type: "toggle" })}
                    onClick={(event) => event.stopPropagation()}
                  />
                </td>
                <td role="gridcell">
                  <span className="fb-name-cell">
                    <FileBeltIcon icon={entry.kind === "folder" ? Folder : File} />
                    <BidiText>{entry.name}</BidiText>
                    {entry.shared ? <FileBeltIcon icon={Share2} size={16} /> : null}
                  </span>
                </td>
                <td role="gridcell"><BidiText>{entry.owner}</BidiText></td>
                <td role="gridcell"><time dateTime={entry.modifiedAt}>{formatDate(entry.modifiedAt)}</time></td>
                <td role="gridcell">{formatBytes(entry.size)}</td>
                <td role="gridcell">
                  {entry.status === "conflict" ? <StatusPill kind="warning"><FileBeltIcon icon={AlertTriangle} size={16} /> {strings.conflict}</StatusPill> : null}
                  {entry.status === "quarantined" ? <StatusPill kind="danger"><FileBeltIcon icon={LockKeyhole} size={16} /> {strings.quarantined}</StatusPill> : null}
                  {entry.status === "ready" ? <StatusPill kind="success">{strings.ready}</StatusPill> : null}
                  {entry.status === "uploading" ? <StatusPill kind="informative">{strings.uploading}</StatusPill> : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
