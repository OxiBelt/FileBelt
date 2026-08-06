// SPDX-License-Identifier: Apache-2.0

import {
  Button,
  Input,
  Menu,
  MenuItem,
  MenuList,
  MenuPopover,
  MenuTrigger,
  Spinner,
  Tooltip,
} from "@fluentui/react-components";
import {
  Bell,
  Clock3,
  CloudUpload,
  Download,
  Files,
  FolderClock,
  FolderInput,
  HardDrive,
  History,
  Link2,
  Menu as MenuIcon,
  Moon,
  MoreHorizontal,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  Sun,
  Trash2,
  Upload,
  Users,
} from "lucide-react";
import { lazy, Suspense, useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import type { ChangeEvent, ReactNode } from "react";

import {
  BidiText,
  BrandMark,
  FileBeltIcon,
  FileBeltProvider,
  StatusPill,
  visuallyHiddenStyle,
} from "@filebelt/design-system";
import type { Density, ThemeChoice } from "@filebelt/design-system";

import { PrivacyView, SessionsView, SharesView, UploadsView, VersionsView } from "./ActivityViews.js";
import { AuthenticationRequiredError } from "./client.js";
import type { FileBeltClient } from "./client.js";
import { FileTable } from "./FileTable.js";
import type { FileEntry, RouteId, WorkspaceSnapshot } from "./model.js";
import { emptySelection, selectionReducer } from "./selection.js";
import { en } from "./strings.js";

const AdminPanel = lazy(() => import("@filebelt/admin"));
const preferencesKey = "filebelt.appearance.v1";

interface Preferences {
  density: Density;
  theme: ThemeChoice;
}

const defaultPreferences: Preferences = { density: "comfortable", theme: "system" };

function loadPreferences(): Preferences {
  try {
    const value = JSON.parse(localStorage.getItem(preferencesKey) ?? "null") as Partial<Preferences> | null;
    const theme = value?.theme;
    const density = value?.density;
    return {
      density: density === "compact" || density === "comfortable" ? density : defaultPreferences.density,
      theme: theme === "light" || theme === "dark" || theme === "system" ? theme : defaultPreferences.theme,
    };
  } catch {
    return defaultPreferences;
  }
}

const routePaths: Record<RouteId, string> = {
  drive: "/drive",
  "shared-drives": "/shared-drives",
  shared: "/shared",
  recent: "/recent",
  trash: "/trash",
  uploads: "/uploads",
  versions: "/versions",
  shares: "/shares",
  sessions: "/sessions",
  privacy: "/privacy",
};

function routeFromPath(pathname: string): RouteId | "admin" {
  if (pathname === "/admin" || pathname.startsWith("/admin/")) return "admin";
  return (Object.entries(routePaths).find(([, path]) => pathname === path)?.[0] as RouteId | undefined) ?? "drive";
}

function useRoute(): [RouteId | "admin", (route: RouteId | "admin") => void] {
  const [route, setRoute] = useState<RouteId | "admin">(() => routeFromPath(window.location.pathname));
  useEffect(() => {
    const onPopState = (): void => setRoute(routeFromPath(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  const navigate = (next: RouteId | "admin"): void => {
    window.history.pushState({}, "", next === "admin" ? "/admin" : routePaths[next]);
    setRoute(next);
  };
  return [route, navigate];
}

function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.download = name;
  anchor.href = url;
  anchor.click();
  URL.revokeObjectURL(url);
}

function routeTitle(route: RouteId | "admin"): string {
  const titles: Record<RouteId | "admin", string> = {
    admin: en.admin,
    drive: en.myDrive,
    privacy: en.privacy,
    recent: en.recent,
    sessions: en.sessions,
    shared: en.shared,
    "shared-drives": en.sharedDrives,
    shares: en.shares,
    trash: en.trash,
    uploads: en.uploads,
    versions: en.versions,
  };
  return titles[route];
}

interface AppProps {
  client: FileBeltClient;
}

export function oidcLoginHref(): string {
  return "/api/v1/auth/login?return_path=%2F";
}

export function SignInPrompt(): ReactNode {
  return (
    <section aria-labelledby="sign-in-heading" className="fb-loading">
      <h1 id="sign-in-heading">{en.signInRequired}</h1>
      <p>{en.signInDescription}</p>
      <Button appearance="primary" as="a" href={oidcLoginHref()}>{en.signIn}</Button>
    </section>
  );
}

export function App({ client }: AppProps): ReactNode {
  const [route, navigate] = useRoute();
  const [snapshot, setSnapshot] = useState<WorkspaceSnapshot | null>(null);
  const [selection, dispatchSelection] = useReducer(selectionReducer, emptySelection);
  const [search, setSearch] = useState("");
  const [preferences, setPreferences] = useState(loadPreferences);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authenticationRequired, setAuthenticationRequired] = useState(false);
  const [announcement, setAnnouncement] = useState("");
  const [actionEntryId, setActionEntryId] = useState<string | null>(null);
  const [navigationOpen, setNavigationOpen] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const handleFailure = useCallback((cause: unknown): void => {
    if (cause instanceof AuthenticationRequiredError) {
      setAuthenticationRequired(true);
      setSnapshot(null);
      setError(null);
      return;
    }
    setError(cause instanceof Error ? cause.message : en.offline);
  }, []);

  const refresh = useCallback(async (signal?: AbortSignal): Promise<void> => {
    try {
      setError(null);
      setSnapshot(await client.getWorkspace(signal));
      setAuthenticationRequired(false);
    } catch (cause) {
      if (!(cause instanceof DOMException && cause.name === "AbortError")) handleFailure(cause);
    }
  }, [client, handleFailure]);

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    return () => controller.abort();
  }, [refresh]);

  useEffect(() => {
    localStorage.setItem(preferencesKey, JSON.stringify(preferences));
  }, [preferences]);

  useEffect(() => {
    setAnnouncement(en.selectedAnnouncement(selection.selectedIds.size));
  }, [selection.selectedIds]);

  const mutate = async (operation: () => Promise<void>, message: string): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await operation();
      await refresh();
      setAnnouncement(message);
    } catch (cause) {
      handleFailure(cause);
    } finally {
      setBusy(false);
    }
  };

  const entries = useMemo(() => {
    if (snapshot === null) return [];
    let result = snapshot.entries;
    if (route === "trash") result = result.filter(({ trashed }) => trashed);
    else result = result.filter(({ trashed }) => !trashed);
    if (route === "shared") result = result.filter(({ owner }) => owner !== snapshot.currentUser.displayName);
    if (route === "shared-drives") result = result.filter(({ shared }) => shared);
    if (route === "recent") result = [...result].sort((left, right) => right.modifiedAt.localeCompare(left.modifiedAt));
    const normalizedSearch = search.trim().toLocaleLowerCase();
    if (normalizedSearch.length > 0) result = result.filter(({ name }) => name.toLocaleLowerCase().includes(normalizedSearch));
    return result;
  }, [route, search, snapshot]);

  const selectedEntries = snapshot?.entries.filter(({ id }) => selection.selectedIds.has(id)) ?? [];
  const primarySelection = selectedEntries.at(-1);
  const actionEntry = snapshot?.entries.find(({ id }) => id === actionEntryId);

  const onFiles = (event: ChangeEvent<HTMLInputElement>): void => {
    const candidates = [...(event.currentTarget.files ?? [])].map((file) => ({ data: file, name: file.name, size: file.size }));
    event.currentTarget.value = "";
    if (candidates.length > 0) void mutate(() => client.upload(candidates), en.uploadCompleted(candidates.length));
  };

  const downloadEntry = async (entry: FileEntry): Promise<void> => {
    if (entry.kind !== "file") return;
    setBusy(true);
    try {
      saveBlob(await client.download(entry.id), entry.name);
      setAnnouncement(en.downloadStarted(entry.name));
    } catch (cause) {
      handleFailure(cause);
    } finally {
      setBusy(false);
    }
  };

  const changePreference = (patch: Partial<Preferences>): void => setPreferences((current) => ({ ...current, ...patch }));

  const navigation: ReadonlyArray<{ icon: typeof Files; id: RouteId | "admin"; label: string }> = [
    { icon: Files, id: "drive", label: en.myDrive },
    { icon: HardDrive, id: "shared-drives", label: en.sharedDrives },
    { icon: Users, id: "shared", label: en.shared },
    { icon: Clock3, id: "recent", label: en.recent },
    { icon: Trash2, id: "trash", label: en.trash },
    { icon: CloudUpload, id: "uploads", label: en.uploads },
    { icon: History, id: "versions", label: en.versions },
    { icon: Link2, id: "shares", label: en.shares },
    { icon: ShieldCheck, id: "sessions", label: en.sessions },
    { icon: Bell, id: "privacy", label: en.privacy },
    ...(snapshot?.currentUser.isTenantAdmin === true ? [{ icon: Settings2, id: "admin" as const, label: en.admin }] : []),
  ];

  return (
    <FileBeltProvider density={preferences.density} themeChoice={preferences.theme}>
      <div className="fb-app-shell">
        <a className="fb-skip-link" href="#main-content">{en.skipToContent}</a>
        <header className="fb-topbar">
          <Button aria-label={en.mainNavigation} appearance="subtle" className="fb-mobile-menu" icon={<MenuIcon />} onClick={() => setNavigationOpen((open) => !open)} />
          <button className="fb-brand" onClick={() => navigate("drive")} type="button"><BrandMark /><span>{en.appName}</span></button>
          <Input className="fb-search" contentBefore={<Search aria-hidden="true" size={18} strokeWidth={1.75} />} onChange={(_, data) => setSearch(data.value)} placeholder={en.search} type="search" value={search} />
          <Menu>
            <MenuTrigger disableButtonEnhancement><Button aria-label={en.userMenu} appearance="subtle"><span className="fb-avatar" aria-hidden="true">AM</span><span className="fb-user-name">{snapshot?.currentUser.displayName ?? en.account}</span></Button></MenuTrigger>
            <MenuPopover><MenuList>
              <MenuItem disabled>{en.theme}</MenuItem>
              <MenuItem icon={<Settings2 />} onClick={() => changePreference({ theme: "system" })}>{en.system}</MenuItem>
              <MenuItem icon={<Sun />} onClick={() => changePreference({ theme: "light" })}>{en.light}</MenuItem>
              <MenuItem icon={<Moon />} onClick={() => changePreference({ theme: "dark" })}>{en.dark}</MenuItem>
              <MenuItem disabled>{en.viewSettings}</MenuItem>
              <MenuItem onClick={() => changePreference({ density: "comfortable" })}>{en.comfortable}</MenuItem>
              <MenuItem onClick={() => changePreference({ density: "compact" })}>{en.compact}</MenuItem>
            </MenuList></MenuPopover>
          </Menu>
        </header>

        <nav aria-label={en.mainNavigation} className={navigationOpen ? "fb-navigation is-open" : "fb-navigation"}>
          {navigation.map((item) => (
            <button aria-current={route === item.id ? "page" : undefined} className={route === item.id ? "fb-nav-item is-active" : "fb-nav-item"} key={item.id} onClick={() => { navigate(item.id); setNavigationOpen(false); }} type="button">
              <FileBeltIcon icon={item.icon} /><span>{item.label}</span>
            </button>
          ))}
        </nav>

        <main className="fb-main" id="main-content" tabIndex={-1}>
          {error === null ? null : <div className="fb-error" role="alert"><span>{error}</span><Button appearance="transparent" onClick={() => void refresh()}>{en.refresh}</Button></div>}
          {authenticationRequired ? <SignInPrompt /> : snapshot === null ? <div className="fb-loading"><Spinner label={en.loading} /></div> : (
            <>
              {route === "admin" && snapshot.currentUser.isTenantAdmin ? (
                <Suspense fallback={<Spinner label={en.loading} />}>
                  <AdminPanel
                    drives={snapshot.admin.drives}
                    groups={snapshot.admin.groups}
                    onCreateGroup={(name) => mutate(() => client.createGroup(name), en.createdGroup(name))}
                    onCreateSharedDrive={(name) => mutate(() => client.createSharedDrive(name), en.createdSharedDrive(name))}
                    onToggleUserSuspension={(id) => mutate(() => client.suspendUser(id), en.userStatusUpdated)}
                    users={snapshot.admin.users}
                  />
                </Suspense>
              ) : null}
              {route === "admin" && !snapshot.currentUser.isTenantAdmin ? <div className="fb-error" role="alert">{en.permissionDenied}</div> : null}
              {route === "uploads" ? <UploadsView strings={en} uploads={snapshot.uploads} /> : null}
              {route === "versions" ? <VersionsView file={primarySelection} onRestore={(id) => mutate(() => client.restoreVersion(id), en.versionRestored)} strings={en} versions={snapshot.versions} /> : null}
              {route === "shares" ? <SharesView file={primarySelection} onCreate={(input) => mutate(() => client.createShare(input), en.shareCreated)} onRevoke={(id) => mutate(() => client.revokeShare(id), en.shareRevoked)} shares={snapshot.shares} strings={en} /> : null}
              {route === "sessions" ? <SessionsView onRevoke={(id) => mutate(() => client.revokeSession(id), en.sessionRevoked)} sessions={snapshot.sessions} strings={en} /> : null}
              {route === "privacy" ? <PrivacyView events={snapshot.privacy} onMarkRead={() => mutate(() => client.markPrivacyRead(), en.privacyRead)} strings={en} /> : null}
              {["drive", "shared-drives", "shared", "recent", "trash"].includes(route) ? (
                <section aria-labelledby="files-heading" className="fb-files-view">
                  <header className="fb-page-heading"><div><p className="fb-eyebrow">{en.files}</p><h1 id="files-heading">{routeTitle(route)}</h1></div><div className="fb-heading-actions"><Tooltip content={en.refresh} relationship="label"><Button appearance="subtle" icon={<RefreshCw />} onClick={() => void refresh()} /></Tooltip><Button appearance="primary" icon={<Upload />} onClick={() => fileInput.current?.click()}>{en.upload}</Button><input accept="*/*" aria-label={en.uploadHint} hidden multiple onChange={onFiles} ref={fileInput} type="file" /></div></header>
                  <div aria-label={en.fileCommands} className="fb-commandbar" role="toolbar">
                    <span>{en.selectedAnnouncement(selection.selectedIds.size)}</span>
                    <Button disabled={primarySelection?.kind !== "file" || busy} icon={<Download />} onClick={() => primarySelection === undefined ? undefined : void downloadEntry(primarySelection)}>{en.download}</Button>
                    <Button disabled={selectedEntries.length === 0 || busy} icon={route === "trash" ? <FolderInput /> : <Trash2 />} onClick={() => void mutate(() => route === "trash" ? client.restoreEntries(selectedEntries.map(({ id }) => id)) : client.trashEntries(selectedEntries.map(({ id }) => id)), route === "trash" ? en.itemsRestored : en.itemsTrashed)}>{route === "trash" ? en.restore : en.moveToTrash}</Button>
                    <Button disabled={primarySelection === undefined} icon={<History />} onClick={() => navigate("versions")}>{en.versions}</Button>
                    <Button disabled={primarySelection === undefined} icon={<Link2 />} onClick={() => navigate("shares")}>{en.shares}</Button>
                  </div>
                  <div className="fb-content-split">
                    <FileTable dispatchSelection={dispatchSelection} entries={entries} onOpenActions={(entry) => { dispatchSelection({ id: entry.id, type: "replace" }); setActionEntryId(entry.id); }} selection={selection} strings={en} />
                    <aside aria-label={en.details} className="fb-details-pane">
                      {primarySelection === undefined ? <p className="fb-muted">{en.noSelection}</p> : <><div className="fb-details-icon"><FileBeltIcon icon={primarySelection.kind === "folder" ? FolderClock : Files} size={28} /></div><h2><BidiText>{primarySelection.name}</BidiText></h2><dl><div><dt>{en.owner}</dt><dd><BidiText>{primarySelection.owner}</BidiText></dd></div><div><dt>{en.version}</dt><dd>{primarySelection.version}</dd></div><div><dt>{en.status}</dt><dd><StatusPill kind="success">{en.ready}</StatusPill></dd></div></dl><Button appearance="secondary" icon={<MoreHorizontal />} onClick={() => setActionEntryId(primarySelection.id)}>{en.openMenu}</Button></>}
                    </aside>
                  </div>
                </section>
              ) : null}
            </>
          )}
        </main>
        {busy ? <div className="fb-working" role="status"><Spinner size="tiny" /><span>{en.working}</span></div> : null}
        <div aria-atomic="true" aria-live="polite" style={visuallyHiddenStyle}>{announcement}</div>
        {actionEntry === undefined ? null : (
          <div className="fb-action-backdrop" onClick={() => setActionEntryId(null)} role="presentation">
            <div aria-label={en.selectionActions} className="fb-action-menu" onClick={(event) => event.stopPropagation()} onKeyDown={(event) => { if (event.key === "Escape") setActionEntryId(null); }} role="menu">
              <strong><BidiText>{actionEntry.name}</BidiText></strong>
              <Button appearance="subtle" disabled={actionEntry.kind !== "file"} icon={<Download />} onClick={() => { setActionEntryId(null); void downloadEntry(actionEntry); }} role="menuitem">{en.download}</Button>
              <Button appearance="subtle" icon={<Link2 />} onClick={() => { setActionEntryId(null); navigate("shares"); }} role="menuitem">{en.shares}</Button>
              <Button appearance="subtle" icon={actionEntry.trashed ? <FolderInput /> : <Trash2 />} onClick={() => { setActionEntryId(null); void mutate(() => actionEntry.trashed ? client.restoreEntries([actionEntry.id]) : client.trashEntries([actionEntry.id]), actionEntry.trashed ? en.itemsRestored : en.itemsTrashed); }} role="menuitem">{actionEntry.trashed ? en.restore : en.moveToTrash}</Button>
              <Button appearance="secondary" onClick={() => setActionEntryId(null)} role="menuitem">{en.close}</Button>
            </div>
          </div>
        )}
      </div>
    </FileBeltProvider>
  );
}
