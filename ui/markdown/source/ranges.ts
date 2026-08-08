// SPDX-License-Identifier: Apache-2.0

/* eslint-disable @typescript-eslint/naming-convention -- mdast positions use exact lowercase external field names. */

import type { SourceRange } from "./types.js";

export interface MarkdownPoint {
  column: number;
  line: number;
  offset?: number;
}

export interface MarkdownPosition {
  end: MarkdownPoint;
  start: MarkdownPoint;
}

export function CreateLineStarts(Source: string): readonly number[] {
  const Starts = [0];
  for (let Index = 0; Index < Source.length; Index += 1) {
    if (Source[Index] === "\n") {
      Starts.push(Index + 1);
    }
  }
  return Starts;
}

export function OffsetFromPoint(Point: MarkdownPoint, LineStarts: readonly number[]): number {
  if (Point.offset !== undefined) {
    return Point.offset;
  }
  const LineStart = LineStarts[Point.line - 1];
  if (LineStart === undefined || Point.column < 1) {
    throw new RangeError("Markdown point is outside the source document.");
  }
  return LineStart + Point.column - 1;
}

export function RangeFromPosition(Position: MarkdownPosition | undefined, LineStarts: readonly number[]): SourceRange {
  if (Position === undefined) {
    return { End: 0, Start: 0 };
  }
  return {
    End: OffsetFromPoint(Position.end, LineStarts),
    Start: OffsetFromPoint(Position.start, LineStarts),
  };
}
