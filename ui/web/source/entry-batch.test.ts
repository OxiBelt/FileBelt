// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { EntryMutationErrorText, SummarizeEntryMutations } from "./entry-batch.js";

describe("entry mutation summaries", () => {
  it("counts successes and keeps each failed item's exact safe problem fields", () => {
    const Error = {
      Code: "node.generation_conflict",
      Detail: "Expected generation 4, but found 5.",
      Message: "The item changed",
      Status: 409,
    } as const;
    const Summary = SummarizeEntryMutations(
      [
        { Id: "first", Name: "First.txt" },
        { Id: "second", Name: "Second.txt" },
      ],
      [
        { EntryId: "first", Kind: "success" },
        { EntryId: "second", Error, Kind: "failure" },
      ],
    );

    expect(Summary).toEqual({
      Failures: [{ EntryId: "second", Error, Name: "Second.txt" }],
      Succeeded: 1,
    });
    expect(EntryMutationErrorText(Error)).toBe(
      "The item changed — Expected generation 4, but found 5. [node.generation_conflict] (HTTP 409)",
    );
  });

  it("fails closed when a client omits an outcome for a requested immutable ID", () => {
    const Summary = SummarizeEntryMutations([{ Id: "missing", Name: "Missing.txt" }], []);

    expect(Summary.Succeeded).toBe(0);
    expect(Summary.Failures[0]).toMatchObject({
      EntryId: "missing",
      Error: { Code: "client.missing_outcome" },
      Name: "Missing.txt",
    });
  });
});
