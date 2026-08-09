// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { IsMediaPlaybackManifestPath, MediaPreview } from "./MediaPreview.js";

const PreviewId = "00000000-0000-4000-8000-000000000001";
const ManifestPath = `/api/v1/media-previews/${PreviewId}/playback/manifest`;

describe("media preview", () => {
  it("accepts only the opaque same-origin cookie playback route", () => {
    expect(IsMediaPlaybackManifestPath(ManifestPath)).toBe(true);
    for (const Value of [
      `${ManifestPath}?token=secret`,
      `${ManifestPath}#fragment`,
      "https://untrusted.example/manifest",
      "/api/v1/media-previews/not-a-uuid/playback/manifest",
    ]) expect(IsMediaPlaybackManifestPath(Value)).toBe(false);
  });

  it("renders native controls and the admitted codec MIME types without autoplay", () => {
    const Av1 = renderToStaticMarkup(<MediaPreview Codec="av1" ManifestPath={ManifestPath} Title="Video" />);
    const Vp9 = renderToStaticMarkup(<MediaPreview Codec="vp9" ManifestPath={ManifestPath} Title="Video" />);
    expect(Av1).toContain('type="video/webm; codecs=av01,opus"');
    expect(Vp9).toContain('type="video/webm; codecs=vp9,opus"');
    expect(Av1).toContain("controls");
    expect(Av1).toContain('controlsList="nodownload noremoteplayback"');
    expect(Av1).toContain('preload="metadata"');
    expect(Av1).not.toContain("autoplay");
    expect(Av1).not.toContain("token=");
  });

  it("never hands an invalid route to a media element", () => {
    const Markup = renderToStaticMarkup(<MediaPreview Codec="vp9" ManifestPath="https://example.invalid/video" Title="Video" />);
    expect(Markup).toContain('role="alert"');
    expect(Markup).not.toContain("<video");
  });
});
