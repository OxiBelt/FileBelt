// SPDX-License-Identifier: Apache-2.0

import type { FileBeltReference } from "./types.js";

const Identifier = "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const ReferencePattern = new RegExp(
  `^filebelt://drive/(${Identifier})/node/(${Identifier})(?:\\?version=(${Identifier}))?$`,
  "i",
);

export function ParseFileBeltReference(Value: string): FileBeltReference | undefined {
  const Match = ReferencePattern.exec(Value);
  if (Match === null) {
    return undefined;
  }

  const DriveId = Match[1];
  const NodeId = Match[2];
  const VersionId = Match[3];
  if (DriveId === undefined || NodeId === undefined) return undefined;
  return VersionId === undefined
    ? { DriveId: DriveId.toLowerCase(), NodeId: NodeId.toLowerCase() }
    : {
        DriveId: DriveId.toLowerCase(),
        NodeId: NodeId.toLowerCase(),
        VersionId: VersionId.toLowerCase(),
      };
}
