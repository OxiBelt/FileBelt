// SPDX-License-Identifier: Apache-2.0

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.js";
import { HttpFileBeltClient } from "./http-client.js";
import { PublicShareApp, TakePublicShareFragment } from "./PublicShareApp.js";
import "./styles.css";

const Root = document.querySelector<HTMLElement>("#root");

if (Root === null) {
  throw new Error("FileBelt application root is missing");
}

const Client = new HttpFileBeltClient();
const IsPublicShare = window.location.pathname.startsWith("/public/share");
const FragmentToken = IsPublicShare ? TakePublicShareFragment() : "";

createRoot(Root).render(
  <StrictMode>
    {IsPublicShare ? <PublicShareApp Client={Client} FragmentToken={FragmentToken} /> : <App Client={Client} />}
  </StrictMode>,
);
