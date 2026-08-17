// SPDX-License-Identifier: Apache-2.0

import type { FileEntry } from "./model.js";

const MaximumOfficeDocumentBytes = 100 * 1024 * 1024;

const OfficeMediaTypes: Readonly<Record<string, string>> = {
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".odp": "application/vnd.oasis.opendocument.presentation",
  ".ods": "application/vnd.oasis.opendocument.spreadsheet",
  ".odt": "application/vnd.oasis.opendocument.text",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
};

/** An exact Office type is eligible for an external document session, not Markdown conversion. */
export function IsOfficeDocumentCandidate(Entry: FileEntry): boolean {
  if (
    Entry.Kind !== "file" ||
    Entry.HeadVersionId === null ||
    Entry.Size === null ||
    Entry.Size > MaximumOfficeDocumentBytes
  )
    return false;
  const Extension = Object.keys(OfficeMediaTypes).find((Candidate) =>
    Entry.Name.endsWith(Candidate),
  );
  return Extension !== undefined && Entry.MediaType === OfficeMediaTypes[Extension];
}
