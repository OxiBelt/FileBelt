// SPDX-License-Identifier: Apache-2.0

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.js";
import { MockFileBeltClient } from "./client.js";
import { HttpFileBeltClient } from "./http-client.js";
import { HttpDocumentSessionClient } from "./document-http-client.js";
import { HttpMcpSettingsClient } from "./mcp-http-client.js";
import { HttpMountSettingsClient } from "./mount-http-client.js";
import { HttpNfsAdminClient } from "./nfs-admin-http-client.js";
import { HttpNfsTargetClient } from "./nfs-target-http-client.js";
import { PublicShareApp, TakePublicShareFragment } from "./PublicShareApp.js";
import { HasDevelopmentMockMarker } from "./navigation.js";
import "./styles.css";

const Root = document.querySelector<HTMLElement>("#root");

if (Root === null) {
  throw new Error("FileBelt application root is missing");
}

const DevelopmentMock = import.meta.env.DEV && HasDevelopmentMockMarker(window.location.search);
const Client = DevelopmentMock ? new MockFileBeltClient() : new HttpFileBeltClient();
const DocumentClient = new HttpDocumentSessionClient();
const McpClient = new HttpMcpSettingsClient();
const MountClient = new HttpMountSettingsClient();
const NfsClient = new HttpNfsAdminClient();
const NfsTargetClient = new HttpNfsTargetClient();
const IsPublicShare = window.location.pathname.startsWith("/public/share");
const FragmentToken = IsPublicShare ? TakePublicShareFragment() : "";

createRoot(Root).render(
  <StrictMode>
    {IsPublicShare ? (
      <PublicShareApp Client={Client} FragmentToken={FragmentToken} />
    ) : (
      <App
        Client={Client}
        DevelopmentMode={DevelopmentMock}
        {...(DevelopmentMock
          ? {}
          : {
              DocumentClient,
              McpClient,
              MountClient,
              NfsClient,
              NfsTargetClient,
            })}
      />
    )}
  </StrictMode>,
);
