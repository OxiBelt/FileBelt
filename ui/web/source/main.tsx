// SPDX-License-Identifier: Apache-2.0

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.js";
import { HttpFileBeltClient } from "./http-client.js";
import { PublicShareApp, takePublicShareFragment } from "./PublicShareApp.js";
import "./styles.css";

const root = document.querySelector<HTMLElement>("#root");

if (root === null) {
  throw new Error("FileBelt application root is missing");
}

const client = new HttpFileBeltClient();
const isPublicShare = window.location.pathname.startsWith("/public/share");
const fragmentToken = isPublicShare ? takePublicShareFragment() : "";

createRoot(root).render(
  <StrictMode>
    {isPublicShare ? <PublicShareApp client={client} fragmentToken={fragmentToken} /> : <App client={client} />}
  </StrictMode>,
);
