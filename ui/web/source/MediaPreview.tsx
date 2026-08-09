// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";

import { MediaPreviewEn } from "./media-strings.js";

export type MediaPreviewCodec = "av1" | "vp9";

export interface MediaPreviewProps {
  /** A same-origin, cookie-authenticated playback-manifest path. */
  readonly ManifestPath: string;
  readonly Codec: MediaPreviewCodec;
  /** Rendered as text; callers must not treat this component as authorization. */
  readonly Title: string;
  readonly OnPlaybackError?: () => void;
}

/**
 * A deliberately isolated playback surface. It accepts only the future
 * cookie-scoped FileBelt playback route: tokens, external origins, fragments,
 * and query strings cannot reach a media element through this component.
 */
export function MediaPreview({ Codec, ManifestPath, OnPlaybackError, Title }: MediaPreviewProps): ReactNode {
  if (!IsMediaPlaybackManifestPath(ManifestPath)) return <p role="alert">{MediaPreviewEn.unavailable}</p>;
  const MimeType = Codec === "av1" ? "video/webm; codecs=av01,opus" : "video/webm; codecs=vp9,opus";
  return <section aria-label={Title}>
    <video controls controlsList="nodownload noremoteplayback" disablePictureInPicture onError={OnPlaybackError} playsInline preload="metadata">
      <source src={ManifestPath} type={MimeType} />
      <p>{MediaPreviewEn.unsupported}</p>
    </video>
  </section>;
}

export function IsMediaPlaybackManifestPath(Value: string): boolean {
  return /^\/api\/v1\/media-previews\/[0-9a-f-]{36}\/playback\/manifest$/.test(Value);
}
