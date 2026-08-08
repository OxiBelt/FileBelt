// SPDX-License-Identifier: Apache-2.0

import { merge } from "node-diff3";

export interface MarkdownMergeResult {
  Conflict: boolean;
  Text: string;
}

export function MergeMarkdownSources(Base: string, Local: string, Remote: string): MarkdownMergeResult {
  const BaseLines = Base.split("\n");
  const LocalLines = Local.split("\n");
  const RemoteLines = Remote.split("\n");
  if (BaseLines.length === LocalLines.length && BaseLines.length === RemoteLines.length) {
    const Resolved: string[] = [];
    let HasOverlappingEdit = false;
    for (let Index = 0; Index < BaseLines.length; Index += 1) {
      const BaseLine = BaseLines[Index] ?? "";
      const LocalLine = LocalLines[Index] ?? "";
      const RemoteLine = RemoteLines[Index] ?? "";
      if (LocalLine === RemoteLine) Resolved.push(LocalLine);
      else if (LocalLine === BaseLine) Resolved.push(RemoteLine);
      else if (RemoteLine === BaseLine) Resolved.push(LocalLine);
      else {
        HasOverlappingEdit = true;
        break;
      }
    }
    if (!HasOverlappingEdit) return { Conflict: false, Text: Resolved.join("\n") };
  }
  const Result = merge(LocalLines, BaseLines, RemoteLines, {
    excludeFalseConflicts: true,
    label: { a: "local FileBelt edits", b: "latest FileBelt version", o: "base FileBelt version" },
  });
  return { Conflict: Result.conflict, Text: Result.result.join("\n") };
}
