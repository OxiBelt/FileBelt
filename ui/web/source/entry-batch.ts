// SPDX-License-Identifier: Apache-2.0

import type { EntryMutationError, EntryMutationOutcome } from './client.js'
import type { FileEntry } from './model.js'

export interface EntryMutationFailureDisplay {
  EntryId: string
  Error: Readonly<EntryMutationError>
  Name: string
}

export interface EntryMutationSummary {
  Failures: readonly Readonly<EntryMutationFailureDisplay>[]
  Succeeded: number
}

export function SummarizeEntryMutations(
  Entries: readonly Readonly<Pick<FileEntry, 'Id' | 'Name'>>[],
  Outcomes: readonly EntryMutationOutcome[],
): EntryMutationSummary {
  const OutcomeById = new Map(Outcomes.map((Outcome) => [Outcome.EntryId, Outcome]))
  const Failures: EntryMutationFailureDisplay[] = []
  let Succeeded = 0
  for (const Entry of Entries) {
    const Outcome = OutcomeById.get(Entry.Id)
    if (Outcome?.Kind === 'success') {
      Succeeded += 1
      continue
    }
    Failures.push({
      EntryId: Entry.Id,
      Error:
        Outcome?.Kind === 'failure'
          ? Outcome.Error
          : {
              Code: 'client.missing_outcome',
              Detail: null,
              Message: 'The server did not return an outcome for this item.',
              Status: null,
            },
      Name: Entry.Name,
    })
  }
  return { Failures, Succeeded }
}

export function EntryMutationErrorText(Error: Readonly<EntryMutationError>): string {
  const Detail = Error.Detail === null || Error.Detail === Error.Message ? '' : ` — ${Error.Detail}`
  const Code = Error.Code === null ? '' : ` [${Error.Code}]`
  const Status = Error.Status === null ? '' : ` (HTTP ${Error.Status})`
  return `${Error.Message}${Detail}${Code}${Status}`
}
