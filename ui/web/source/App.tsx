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
  FilePenLine,
  FileOutput,
  Files,
  FolderClock,
  FolderInput,
  HardDrive,
  History,
  Link2,
  Menu as MenuIcon,
  Moon,
  MoreHorizontal,
  Network,
  RefreshCw,
  Search as SearchIcon,
  ServerCog,
  Settings2,
  ShieldCheck,
  Sun,
  Trash2,
  Upload,
  Users,
} from "lucide-react";
import { lazy, Suspense, useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import type { ChangeEvent, ReactNode } from "react";
import type { FileBeltReference } from "@filebelt/markdown";

import {
  BidiText,
  BrandMark,
  FileBeltIcon,
  FileBeltProvider,
  StatusPill,
  VisuallyHiddenStyle,
} from "@filebelt/design-system";
import type { Density, ThemeChoice } from "@filebelt/design-system";
import type { McpSettingsClient } from "@filebelt/mcp-settings";

import { PrivacyView, SessionsView, SharesView, UploadsView, VersionsView } from "./ActivityViews.js";
import { AuthenticationRequiredError } from "./client.js";
import type { FileBeltClient } from "./client.js";
import { FileTable } from "./FileTable.js";
import type { FileEntry, RouteId, WorkspaceSnapshot } from "./model.js";
import type { MountSettingsClient } from "./mount-http-client.js";
import { EmptySelection, SelectionReducer } from "./selection.js";
import { En } from "./strings.js";

const AdminPanel = lazy(() => import("@filebelt/admin"));
const McpSettings = lazy(() => import("@filebelt/mcp-settings"));
const MountSettings = lazy(async () => ({ default: (await import("./MountSettings.js")).MountSettings }));
const MarkdownFileView = lazy(async () => ({ default: (await import("./MarkdownFileView.js")).MarkdownFileView }));
const PreferencesKey = "filebelt.appearance.v1";

interface Preferences {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Existing `filebelt.appearance.v1` records persist this JSON key.
  density: Density;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Existing `filebelt.appearance.v1` records persist this JSON key.
  theme: ThemeChoice;
}

const DefaultPreferences: Preferences = { density: "comfortable", theme: "system" };

function LoadPreferences(): Preferences {
  try {
    const Value = JSON.parse(localStorage.getItem(PreferencesKey) ?? "null") as Partial<Preferences> | null;
    const Theme = Value?.theme;
    const Density = Value?.density;
    return {
      density: Density === "compact" || Density === "comfortable" ? Density : DefaultPreferences.density,
      theme: Theme === "light" || Theme === "dark" || Theme === "system" ? Theme : DefaultPreferences.theme,
    };
  } catch {
    return DefaultPreferences;
  }
}

const RoutePaths: Record<RouteId, string> = {
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
  mcp: "/settings/mcp",
  mounts: "/settings/mounts",
  markdown: "/markdown",
};

function RouteFromPath(Pathname: string): RouteId | "admin" {
  if (Pathname === "/admin" || Pathname.startsWith("/admin/")) return "admin";
  if (Pathname === "/settings/mcp" || Pathname.startsWith("/settings/mcp/")) return "mcp";
  if (Pathname === "/settings/mounts") return "mounts";
  if (/^\/markdown\/[0-9a-f-]+$/i.test(Pathname)) return "markdown";
  return (Object.entries(RoutePaths).find(([, Path]) => Pathname === Path)?.[0] as RouteId | undefined) ?? "drive";
}

export type NavigationGuard = (Continue: () => void) => void;

function useRoute(): [RouteId | "admin", (Route: RouteId | "admin") => void, (EntryId: string) => void, (Guard: NavigationGuard | undefined) => void] {
  const [Route, SetRoute] = useState<RouteId | "admin">(() => RouteFromPath(window.location.pathname));
  const ActivePathReference = useRef(window.location.pathname);
  const GuardReference = useRef<NavigationGuard | undefined>(undefined);
  useEffect(() => {
    const OnPopState = (): void => {
      const NextPath = window.location.pathname;
      const NextRoute = RouteFromPath(NextPath);
      const Guard = GuardReference.current;
      if (Guard === undefined) {
        ActivePathReference.current = NextPath;
        SetRoute(NextRoute);
        return;
      }
      // The browser already changed history. Restore the active route until the
      // user chooses how to handle its unsaved source.
      window.history.pushState({}, "", ActivePathReference.current);
      Guard(() => {
        window.history.pushState({}, "", NextPath);
        ActivePathReference.current = NextPath;
        SetRoute(NextRoute);
      });
    };
    window.addEventListener("popstate", OnPopState);
    return () => window.removeEventListener("popstate", OnPopState);
  }, [Route]);
  const Guarded = (Continue: () => void): void => {
    const Guard = GuardReference.current;
    if (Guard === undefined) Continue();
    else Guard(Continue);
  };
  const Navigate = (Next: RouteId | "admin"): void => {
    Guarded(() => {
      const NextPath = Next === "admin" ? "/admin" : RoutePaths[Next];
      window.history.pushState({}, "", NextPath);
      ActivePathReference.current = NextPath;
      SetRoute(Next);
    });
  };
  const OpenMarkdown = (EntryId: string): void => {
    Guarded(() => {
      const NextPath = `/markdown/${EntryId}`;
      window.history.pushState({}, "", NextPath);
      ActivePathReference.current = NextPath;
      SetRoute("markdown");
    });
  };
  return [Route, Navigate, OpenMarkdown, (Guard: NavigationGuard | undefined) => { GuardReference.current = Guard; }];
}

function SaveBlob(Blob: Blob, Name: string): void {
  const Url = URL.createObjectURL(Blob);
  const Anchor = document.createElement("a");
  Anchor.download = Name;
  Anchor.href = Url;
  Anchor.click();
  URL.revokeObjectURL(Url);
}

function RouteTitle(Route: RouteId | "admin"): string {
  const Titles: Record<RouteId | "admin", string> = {
    admin: En.admin,
    drive: En.myDrive,
    mcp: En.mcp,
    mounts: En.mounts,
    markdown: En.markdown,
    privacy: En.privacy,
    recent: En.recent,
    sessions: En.sessions,
    shared: En.shared,
    "shared-drives": En.sharedDrives,
    shares: En.shares,
    trash: En.trash,
    uploads: En.uploads,
    versions: En.versions,
  };
  return Titles[Route];
}

interface AppProps {
  Client: FileBeltClient;
  McpClient?: McpSettingsClient;
  MountClient?: MountSettingsClient;
}

export function OidcLoginHref(): string {
  return "/api/v1/auth/login?return_path=%2F";
}

export function SignInPrompt(): ReactNode {
  return (
    <section aria-labelledby="sign-in-heading" className="fb-loading">
      <h1 id="sign-in-heading">{En.signInRequired}</h1>
      <p>{En.signInDescription}</p>
      <Button appearance="primary" as="a" href={OidcLoginHref()}>{En.signIn}</Button>
    </section>
  );
}

export function App({ Client, McpClient, MountClient }: AppProps): ReactNode {
  const [Route, Navigate, OpenMarkdown, SetNavigationGuard] = useRoute();
  const [Snapshot, SetSnapshot] = useState<WorkspaceSnapshot | null>(null);
  const [Selection, DispatchSelection] = useReducer(SelectionReducer, EmptySelection);
  const [Search, SetSearch] = useState("");
  const [Preferences, SetPreferences] = useState(LoadPreferences);
  const [Busy, SetBusy] = useState(false);
  const [ErrorMessage, SetError] = useState<string | null>(null);
  const [AuthenticationRequired, SetAuthenticationRequired] = useState(false);
  const [Announcement, SetAnnouncement] = useState("");
  const [ActionEntryId, SetActionEntryId] = useState<string | null>(null);
  const [NavigationOpen, SetNavigationOpen] = useState(false);
  const FileInput = useRef<HTMLInputElement>(null);

  const HandleFailure = useCallback((Cause: unknown): void => {
    if (Cause instanceof AuthenticationRequiredError) {
      SetAuthenticationRequired(true);
      SetSnapshot(null);
      SetError(null);
      return;
    }
    SetError(Cause instanceof Error ? Cause.message : En.offline);
  }, []);

  const Refresh = useCallback(async (Signal?: AbortSignal): Promise<void> => {
    try {
      SetError(null);
      SetSnapshot(await Client.getWorkspace(Signal));
      SetAuthenticationRequired(false);
    } catch (Cause) {
      if (!(Cause instanceof DOMException && Cause.name === "AbortError")) HandleFailure(Cause);
    }
  }, [Client, HandleFailure]);

  useEffect(() => {
    const Controller = new AbortController();
    void Refresh(Controller.signal);
    return () => Controller.abort();
  }, [Refresh]);

  useEffect(() => {
    localStorage.setItem(PreferencesKey, JSON.stringify(Preferences));
  }, [Preferences]);

  useEffect(() => {
    SetAnnouncement(En.selectedAnnouncement(Selection.SelectedIds.size));
  }, [Selection.SelectedIds]);

  const Mutate = async (Operation: () => Promise<void>, Message: string): Promise<void> => {
    SetBusy(true);
    SetError(null);
    try {
      await Operation();
      await Refresh();
      SetAnnouncement(Message);
    } catch (Cause) {
      HandleFailure(Cause);
    } finally {
      SetBusy(false);
    }
  };

  const Entries = useMemo(() => {
    if (Snapshot === null) return [];
    let Result = Snapshot.Entries;
    if (Route === "trash") Result = Result.filter(({ Trashed }) => Trashed);
    else Result = Result.filter(({ Trashed }) => !Trashed);
    if (Route === "shared") Result = Result.filter(({ Owner }) => Owner !== Snapshot.CurrentUser.DisplayName);
    if (Route === "shared-drives") Result = Result.filter(({ Shared }) => Shared);
    if (Route === "recent") Result = [...Result].sort((Left, Right) => Right.ModifiedAt.localeCompare(Left.ModifiedAt));
    const NormalizedSearch = Search.trim().toLocaleLowerCase();
    if (NormalizedSearch.length > 0) Result = Result.filter(({ Name }) => Name.toLocaleLowerCase().includes(NormalizedSearch));
    return Result;
  }, [Route, Search, Snapshot]);

  const SelectedEntries = Snapshot?.Entries.filter(({ Id }) => Selection.SelectedIds.has(Id)) ?? [];
  const PrimarySelection = SelectedEntries.at(-1);
  const ActionEntry = Snapshot?.Entries.find(({ Id }) => Id === ActionEntryId);
  const MarkdownEntryId = Route === "markdown" ? window.location.pathname.split("/")[2] : undefined;
  const MarkdownEntry = Snapshot?.Entries.find(({ Id }) => Id === MarkdownEntryId);
  const OpenFileBeltReference = (Target: FileBeltReference): boolean => {
    // Snapshot membership is a UX hint only; the destination read still obtains
    // a new server-authorized grant before rendering any content.
    if (!Snapshot?.Entries.some(({ Id }) => Id === Target.NodeId)) return false;
    OpenMarkdown(Target.NodeId);
    return true;
  };

  const OnFiles = (Event: ChangeEvent<HTMLInputElement>): void => {
    const Candidates = [...(Event.currentTarget.files ?? [])].map((File) => ({ Data: File, ...(File.type.length === 0 ? {} : { MediaType: File.type }), Name: File.name, Size: File.size }));
    Event.currentTarget.value = "";
    if (Candidates.length > 0) void Mutate(() => Client.upload(Candidates), En.uploadCompleted(Candidates.length));
  };

  const DownloadEntry = async (Entry: FileEntry): Promise<void> => {
    if (Entry.Kind !== "file") return;
    SetBusy(true);
    try {
      SaveBlob(await Client.download(Entry.Id), Entry.Name);
      SetAnnouncement(En.downloadStarted(Entry.Name));
    } catch (Cause) {
      HandleFailure(Cause);
    } finally {
      SetBusy(false);
    }
  };

  const ImportOfficeEntry = async (Entry: FileEntry): Promise<void> => {
    if (Entry.Kind !== "file" || Entry.HeadVersionId === null || !IsOfficeImportCandidate(Entry)) return;
    const TargetName = MarkdownImportName(Entry.Name);
    await Mutate(async () => {
      const Markdown = await import("@filebelt/markdown");
      const SourceType = Markdown.OfficeImportType(Entry.Name);
      if (SourceType === null) throw new Error(En.markdownImportUnavailable);
      const Source = await Client.readMarkdown(Entry.Id, Entry.HeadVersionId as string);
      const Contents = new Uint8Array(await Source.arrayBuffer());
      const Converted = await Markdown.ImportOfficeMarkdown({ Contents, SourceType });
      await Client.importMarkdown({ Contents: new Blob([Converted], { type: "text/markdown" }), EntryId: Entry.Id, SourceVersionId: Entry.HeadVersionId as string, TargetName });
    }, En.markdownImportCompleted(TargetName));
  };

  const ChangePreference = (Patch: Partial<Preferences>): void => SetPreferences((Current) => ({ ...Current, ...Patch }));

  const Navigation: ReadonlyArray<{ Icon: typeof Files; Id: RouteId | "admin"; Label: string }> = [
    { Icon: Files, Id: "drive", Label: En.myDrive },
    { Icon: HardDrive, Id: "shared-drives", Label: En.sharedDrives },
    { Icon: Users, Id: "shared", Label: En.shared },
    { Icon: Clock3, Id: "recent", Label: En.recent },
    { Icon: Trash2, Id: "trash", Label: En.trash },
    { Icon: CloudUpload, Id: "uploads", Label: En.uploads },
    { Icon: History, Id: "versions", Label: En.versions },
    { Icon: Link2, Id: "shares", Label: En.shares },
    { Icon: ShieldCheck, Id: "sessions", Label: En.sessions },
    { Icon: Bell, Id: "privacy", Label: En.privacy },
    { Icon: ServerCog, Id: "mcp", Label: En.mcp },
    { Icon: Network, Id: "mounts", Label: En.mounts },
    ...(Snapshot?.CurrentUser.IsTenantAdmin === true ? [{ Icon: Settings2, Id: "admin" as const, Label: En.admin }] : []),
  ];

  return (
    <FileBeltProvider Density={Preferences.density} ThemeChoice={Preferences.theme}>
      <div className="fb-app-shell">
        <a className="fb-skip-link" href="#main-content">{En.skipToContent}</a>
        <header className="fb-topbar">
          <Button aria-label={En.mainNavigation} appearance="subtle" className="fb-mobile-menu" icon={<MenuIcon />} onClick={() => SetNavigationOpen((Open) => !Open)} />
          <button className="fb-brand" onClick={() => Navigate("drive")} type="button"><BrandMark /><span>{En.appName}</span></button>
          <Input className="fb-search" contentBefore={<SearchIcon aria-hidden="true" size={18} strokeWidth={1.75} />} onChange={(Ignored, Data) => SetSearch(Data.value)} placeholder={En.search} type="search" value={Search} />
          <Menu>
            <MenuTrigger disableButtonEnhancement><Button aria-label={En.userMenu} appearance="subtle"><span className="fb-avatar" aria-hidden="true">AM</span><span className="fb-user-name">{Snapshot?.CurrentUser.DisplayName ?? En.account}</span></Button></MenuTrigger>
            <MenuPopover><MenuList>
              <MenuItem disabled>{En.theme}</MenuItem>
              <MenuItem icon={<Settings2 />} onClick={() => ChangePreference({ theme: "system" })}>{En.system}</MenuItem>
              <MenuItem icon={<Sun />} onClick={() => ChangePreference({ theme: "light" })}>{En.light}</MenuItem>
              <MenuItem icon={<Moon />} onClick={() => ChangePreference({ theme: "dark" })}>{En.dark}</MenuItem>
              <MenuItem disabled>{En.viewSettings}</MenuItem>
              <MenuItem onClick={() => ChangePreference({ density: "comfortable" })}>{En.comfortable}</MenuItem>
              <MenuItem onClick={() => ChangePreference({ density: "compact" })}>{En.compact}</MenuItem>
            </MenuList></MenuPopover>
          </Menu>
        </header>

        <nav aria-label={En.mainNavigation} className={NavigationOpen ? "fb-navigation is-open" : "fb-navigation"}>
          {Navigation.map((Item) => (
            <button aria-current={Route === Item.Id ? "page" : undefined} className={Route === Item.Id ? "fb-nav-item is-active" : "fb-nav-item"} key={Item.Id} onClick={() => { Navigate(Item.Id); SetNavigationOpen(false); }} type="button">
              <FileBeltIcon Icon={Item.Icon} /><span>{Item.Label}</span>
            </button>
          ))}
        </nav>

        <main className="fb-main" id="main-content" tabIndex={-1}>
          {ErrorMessage === null ? null : <div className="fb-error" role="alert"><span>{ErrorMessage}</span><Button appearance="transparent" onClick={() => void Refresh()}>{En.refresh}</Button></div>}
          {AuthenticationRequired ? <SignInPrompt /> : Snapshot === null ? <div className="fb-loading"><Spinner label={En.loading} /></div> : (
            <>
              {Route === "admin" && Snapshot.CurrentUser.IsTenantAdmin ? (
                <Suspense fallback={<Spinner label={En.loading} />}>
                  <AdminPanel
                    Drives={Snapshot.Admin.Drives}
                    Groups={Snapshot.Admin.Groups}
                    onCreateGroup={(Name) => Mutate(() => Client.createGroup(Name), En.createdGroup(Name))}
                    onCreateSharedDrive={(Name) => Mutate(() => Client.createSharedDrive(Name), En.createdSharedDrive(Name))}
                    onToggleUserSuspension={(Id) => Mutate(() => Client.suspendUser(Id), En.userStatusUpdated)}
                    Users={Snapshot.Admin.Users}
                  />
                </Suspense>
              ) : null}
              {Route === "admin" && !Snapshot.CurrentUser.IsTenantAdmin ? <div className="fb-error" role="alert">{En.permissionDenied}</div> : null}
              {Route === "uploads" ? <UploadsView Strings={En} Uploads={Snapshot.Uploads} /> : null}
              {Route === "versions" ? <VersionsView File={PrimarySelection} onRestore={(Id) => Mutate(() => Client.restoreVersion(Id), En.versionRestored)} Strings={En} Versions={Snapshot.Versions} /> : null}
              {Route === "shares" ? <SharesView File={PrimarySelection} onCreate={(Input) => Mutate(() => Client.createShare(Input), En.shareCreated)} onRevoke={(Id) => Mutate(() => Client.revokeShare(Id), En.shareRevoked)} Shares={Snapshot.Shares} Strings={En} /> : null}
              {Route === "sessions" ? <SessionsView onRevoke={(Id) => Mutate(() => Client.revokeSession(Id), En.sessionRevoked)} Sessions={Snapshot.Sessions} Strings={En} /> : null}
              {Route === "privacy" ? <PrivacyView Events={Snapshot.Privacy} onMarkRead={() => Mutate(() => Client.markPrivacyRead(), En.privacyRead)} Strings={En} /> : null}
              {Route === "mcp" && McpClient !== undefined ? <Suspense fallback={<Spinner label={En.loading} />}><McpSettings Client={McpClient} IsTenantAdmin={Snapshot.CurrentUser.IsTenantAdmin} /></Suspense> : null}
              {Route === "mcp" && McpClient === undefined ? <div className="fb-error" role="alert">MCP settings are unavailable.</div> : null}
              {Route === "mounts" && MountClient !== undefined ? <Suspense fallback={<Spinner label={En.loading} />}><MountSettings Client={MountClient} /></Suspense> : null}
              {Route === "mounts" && MountClient === undefined ? <div className="fb-error" role="alert">Mount settings are unavailable.</div> : null}
              {Route === "markdown" && MarkdownEntry !== undefined ? <Suspense fallback={<Spinner label={En.markdownLoading} />}><MarkdownFileView Client={Client} Entry={MarkdownEntry} {...(McpClient === undefined ? {} : { McpClient })} OnClose={() => Navigate("drive")} OnFileBeltLink={OpenFileBeltReference} OnNavigationGuardChange={SetNavigationGuard} OnSaved={() => void Refresh()} /></Suspense> : null}
              {Route === "markdown" && MarkdownEntry === undefined ? <div className="fb-error" role="alert">{En.markdownUnavailable}</div> : null}
              {["drive", "shared-drives", "shared", "recent", "trash"].includes(Route) ? (
                <section aria-labelledby="files-heading" className="fb-files-view">
                  <header className="fb-page-heading"><div><p className="fb-eyebrow">{En.files}</p><h1 id="files-heading">{RouteTitle(Route)}</h1></div><div className="fb-heading-actions"><Tooltip content={En.refresh} relationship="label"><Button appearance="subtle" icon={<RefreshCw />} onClick={() => void Refresh()} /></Tooltip><Button appearance="primary" icon={<Upload />} onClick={() => FileInput.current?.click()}>{En.upload}</Button><input accept="*/*" aria-label={En.uploadHint} hidden multiple onChange={OnFiles} ref={FileInput} type="file" /></div></header>
                  <div aria-label={En.fileCommands} className="fb-commandbar" role="toolbar">
                    <span>{En.selectedAnnouncement(Selection.SelectedIds.size)}</span>
                    <Button disabled={PrimarySelection?.Kind !== "file" || Busy} icon={<Download />} onClick={() => PrimarySelection === undefined ? undefined : void DownloadEntry(PrimarySelection)}>{En.download}</Button>
                    <Button disabled={SelectedEntries.length === 0 || Busy} icon={Route === "trash" ? <FolderInput /> : <Trash2 />} onClick={() => void Mutate(() => Route === "trash" ? Client.restoreEntries(SelectedEntries.map(({ Id }) => Id)) : Client.trashEntries(SelectedEntries.map(({ Id }) => Id)), Route === "trash" ? En.itemsRestored : En.itemsTrashed)}>{Route === "trash" ? En.restore : En.moveToTrash}</Button>
                    <Button disabled={PrimarySelection === undefined} icon={<History />} onClick={() => Navigate("versions")}>{En.versions}</Button>
                    <Button disabled={PrimarySelection === undefined} icon={<Link2 />} onClick={() => Navigate("shares")}>{En.shares}</Button>
                    <Button disabled={PrimarySelection === undefined || PrimarySelection.MarkdownEligibility === "ineligible"} icon={<FilePenLine />} onClick={() => PrimarySelection === undefined ? undefined : OpenMarkdown(PrimarySelection.Id)}>{En.openMarkdown}</Button>
                    <Button disabled={PrimarySelection === undefined || !IsOfficeImportCandidate(PrimarySelection) || Busy} icon={<FileOutput />} onClick={() => PrimarySelection === undefined ? undefined : void ImportOfficeEntry(PrimarySelection)}>{En.importMarkdown}</Button>
                  </div>
                  <div className="fb-content-split">
                    <FileTable dispatchSelection={DispatchSelection} Entries={Entries} onOpenActions={(Entry) => { DispatchSelection({ Id: Entry.Id, Type: "replace" }); SetActionEntryId(Entry.Id); }} onOpenEntry={(Entry) => OpenMarkdown(Entry.Id)} Selection={Selection} Strings={En} />
                    <aside aria-label={En.details} className="fb-details-pane">
                      {PrimarySelection === undefined ? <p className="fb-muted">{En.noSelection}</p> : <><div className="fb-details-icon"><FileBeltIcon Icon={PrimarySelection.Kind === "folder" ? FolderClock : Files} size={28} /></div><h2><BidiText>{PrimarySelection.Name}</BidiText></h2><dl><div><dt>{En.owner}</dt><dd><BidiText>{PrimarySelection.Owner}</BidiText></dd></div><div><dt>{En.version}</dt><dd>{PrimarySelection.Version}</dd></div><div><dt>{En.status}</dt><dd><StatusPill Kind="success">{En.ready}</StatusPill></dd></div></dl><Button appearance="secondary" icon={<MoreHorizontal />} onClick={() => SetActionEntryId(PrimarySelection.Id)}>{En.openMenu}</Button></>}
                    </aside>
                  </div>
                </section>
              ) : null}
            </>
          )}
        </main>
        {Busy ? <div className="fb-working" role="status"><Spinner size="tiny" /><span>{En.working}</span></div> : null}
        <div aria-atomic="true" aria-live="polite" style={VisuallyHiddenStyle}>{Announcement}</div>
        {ActionEntry === undefined ? null : (
          <div className="fb-action-backdrop" onClick={() => SetActionEntryId(null)} role="presentation">
            <div aria-label={En.selectionActions} className="fb-action-menu" onClick={(Event) => Event.stopPropagation()} onKeyDown={(Event) => { if (Event.key === "Escape") SetActionEntryId(null); }} role="menu">
              <strong><BidiText>{ActionEntry.Name}</BidiText></strong>
              <Button appearance="subtle" disabled={ActionEntry.MarkdownEligibility === "ineligible"} icon={<FilePenLine />} onClick={() => { SetActionEntryId(null); OpenMarkdown(ActionEntry.Id); }} role="menuitem">{En.openMarkdown}</Button>
              <Button appearance="subtle" disabled={ActionEntry.Kind !== "file"} icon={<Download />} onClick={() => { SetActionEntryId(null); void DownloadEntry(ActionEntry); }} role="menuitem">{En.download}</Button>
              <Button appearance="subtle" disabled={!IsOfficeImportCandidate(ActionEntry) || Busy} icon={<FileOutput />} onClick={() => { SetActionEntryId(null); void ImportOfficeEntry(ActionEntry); }} role="menuitem">{En.importMarkdown}</Button>
              <Button appearance="subtle" icon={<Link2 />} onClick={() => { SetActionEntryId(null); Navigate("shares"); }} role="menuitem">{En.shares}</Button>
              <Button appearance="subtle" icon={ActionEntry.Trashed ? <FolderInput /> : <Trash2 />} onClick={() => { SetActionEntryId(null); void Mutate(() => ActionEntry.Trashed ? Client.restoreEntries([ActionEntry.Id]) : Client.trashEntries([ActionEntry.Id]), ActionEntry.Trashed ? En.itemsRestored : En.itemsTrashed); }} role="menuitem">{ActionEntry.Trashed ? En.restore : En.moveToTrash}</Button>
              <Button appearance="secondary" onClick={() => SetActionEntryId(null)} role="menuitem">{En.close}</Button>
            </div>
          </div>
        )}
      </div>
    </FileBeltProvider>
  );
}

function IsOfficeImportCandidate(Entry: FileEntry): boolean {
  return Entry.Kind === "file" && Entry.HeadVersionId !== null && Entry.Size !== null && Entry.Size <= 8 * 1024 * 1024 && /\.(?:csv|docx|odp|ods|odt|pptx|rtf|xlsx)$/i.test(Entry.Name);
}

function MarkdownImportName(Name: string): string {
  return `${Name.replace(/\.[^.]+$/, "") || "Imported document"}.md`;
}
