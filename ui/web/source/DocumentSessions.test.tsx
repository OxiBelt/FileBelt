// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { IsIsolatedDocumentLaunchAction, IsOfficeDocumentCandidate } from "./DocumentSessions.js";
import type { FileEntry } from "./model.js";

const Office: FileEntry = {
  DriveId: "00000000-0000-4000-8000-000000000001",
  HeadVersionId: "00000000-0000-4000-8000-000000000002",
  Id: "00000000-0000-4000-8000-000000000003",
  Kind: "file",
  TextEligibility: "ineligible",
  MediaType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ModifiedAt: "2026-08-09T10:00:00Z",
  Name: "Plan.docx",
  Owner: "Avery Morgan",
  Shared: false,
  Size: 100 * 1024 * 1024,
  Status: "ready",
  Trashed: false,
  Version: 1,
};

describe("document session controls", () => {
  it("accepts exact OOXML and ODF document types through 100 MiB", () => {
    expect(IsOfficeDocumentCandidate(Office)).toBe(true);
    expect(IsOfficeDocumentCandidate({ ...Office, MediaType: "application/vnd.oasis.opendocument.text", Name: "Plan.odt" })).toBe(true);
    expect(IsOfficeDocumentCandidate({ ...Office, MediaType: "application/vnd.oasis.opendocument.text", Name: "Plan.ODT" })).toBe(false);
    expect(IsOfficeDocumentCandidate({ ...Office, MediaType: "application/octet-stream" })).toBe(false);
    expect(IsOfficeDocumentCandidate({ ...Office, Name: "Plan.pdf" })).toBe(false);
    expect(IsOfficeDocumentCandidate({ ...Office, Size: 100 * 1024 * 1024 + 1 })).toBe(false);
  });

  it("prepares consent before issuing a one-use handoff and keeps it out of state", async () => {
    const Source = await import("node:fs/promises").then((Fs) => Fs.readFile(new URL("./DocumentSessions.tsx", import.meta.url), "utf8"));
    expect(Source).toContain("En.documentConsent");
    expect(Source).toContain("En.documentConsentCollaborators");
    expect(Source).toContain("SetPreparedLaunch({ ProviderOrigin: Detail.provider_origin, SessionId: Detail.session.id })");
    expect(Source).toContain("Client.redeemLaunch(PreparedLaunch.SessionId)");
    expect(Source).toContain("PreparedLaunch.ProviderOrigin");
    expect(Source).not.toContain("window.location.origin");
    const AfterCreation = Source.slice(Source.indexOf("const Detail = await Client.createSession"));
    expect(AfterCreation).toContain("SetPreparedLaunch({ ProviderOrigin: Detail.provider_origin, SessionId: Detail.session.id })");
    expect(AfterCreation).not.toContain("redeemLaunch(Detail.session.id)");
    expect(Source).not.toContain("useState<DocumentSessionLaunchHandoff");
    expect(Source).toContain("IsIsolatedDocumentLaunchAction(Handoff.action, window.location.hostname)");
    expect(Source).toContain("Form.method = \"post\"");
    expect(Source).toContain("Form.target = \"_self\"");
    expect(Source).toContain("Grant.name = \"launch_grant\"");
    expect(Source).not.toMatch(/(?:localStorage|sessionStorage|indexedDB)\s*[.(]|documents\/api\.js/);
  });

  it("accepts only an isolated HTTPS editor launch action", () => {
    expect(IsIsolatedDocumentLaunchAction("https://editor.example.test/onlyoffice/launch", "files.example.test")).toBe(true);
    expect(IsIsolatedDocumentLaunchAction("https://files.example.test/onlyoffice/launch", "files.example.test")).toBe(false);
    expect(IsIsolatedDocumentLaunchAction("https://files.example.test:8443/onlyoffice/launch", "files.example.test")).toBe(false);
    expect(IsIsolatedDocumentLaunchAction("https://editor.example.test:8443/onlyoffice/launch", "files.example.test")).toBe(false);
    expect(IsIsolatedDocumentLaunchAction("https://editor.example.test./onlyoffice/launch", "files.example.test")).toBe(false);
    expect(IsIsolatedDocumentLaunchAction("http://editor.example.test/onlyoffice/launch", "files.example.test")).toBe(false);
    expect(IsIsolatedDocumentLaunchAction("https://editor.example.test/integrations/launch", "files.example.test")).toBe(false);
    expect(IsIsolatedDocumentLaunchAction("https://editor.example.test/onlyoffice/launch?grant=leak", "files.example.test")).toBe(false);
  });

  it("surfaces detail failures, follows pagination, and refreshes conflict copies", async () => {
    const Source = await import("node:fs/promises").then((Fs) => Fs.readFile(new URL("./DocumentSessions.tsx", import.meta.url), "utf8"));
    expect(Source).toContain("Client.listOwnSessions({ Cursor })");
    expect(Source).toContain("OnFailure(Cause)");
    expect(Source).toContain("if (WorkspaceChanged) await OnWorkspaceChanged?.()");
    expect(Source).toContain("En.documentLoadMore");
  });
});
