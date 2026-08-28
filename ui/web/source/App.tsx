// SPDX-License-Identifier: Apache-2.0

import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Input,
  Menu,
  MenuItem,
  MenuList,
  MenuPopover,
  MenuTrigger,
  Spinner,
  Tooltip,
} from '@fluentui/react-components'
import {
  AlertTriangle,
  ArrowLeft,
  Bell,
  Clock3,
  CloudUpload,
  Download,
  FilePenLine,
  FileOutput,
  FileSymlink,
  Files,
  FolderClock,
  FolderInput,
  HardDrive,
  History,
  Link2,
  LockKeyhole,
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
} from 'lucide-react'
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from 'react'
import type { ChangeEvent, ReactNode } from 'react'
import type { FileBeltReference } from '@filebelt/markdown'

import {
  BidiText,
  BrandMark,
  FileBeltIcon,
  FileBeltProvider,
  StatusPill,
  VisuallyHiddenStyle,
} from '@filebelt/design-system'
import type { Density, ThemeChoice } from '@filebelt/design-system'
import type { NfsAdminClient } from '@filebelt/admin'
import type { McpSettingsClient } from '@filebelt/mcp-settings'

import {
  PrivacyView,
  SessionsView,
  SharesView,
  UploadsView,
  VersionsView,
} from './ActivityViews.js'
import { AuthenticationRequiredError } from './client.js'
import type { EntryMutationOutcome, FileBeltClient, WorkspaceLoadScope } from './client.js'
import type { DocumentSessionClient } from './document-http-client.js'
import { IsOfficeDocumentCandidate } from './document-eligibility.js'
import { FileTable } from './FileTable.js'
import { EntryMutationErrorText, SummarizeEntryMutations } from './entry-batch.js'
import type { EntryMutationSummary } from './entry-batch.js'
import type { FileEntry, RouteId, WorkspaceSnapshot } from './model.js'
import type { MountSettingsClient } from './mount-http-client.js'
import { InternalNavigationHref } from './navigation.js'
import type { NfsTargetClient } from './nfs-target-http-client.js'
import { EmptySelection, SelectionReducer } from './selection.js'
import { En } from './strings.js'

const AdminPanel = lazy(async () => import('@filebelt/admin'))
const McpSettings = lazy(async () => import('@filebelt/mcp-settings'))
const MountSettings = lazy(async () => ({
  default: (await import('./MountSettings.js')).MountSettings,
}))
const MarkdownFileView = lazy(async () => ({
  default: (await import('./MarkdownFileView.js')).MarkdownFileView,
}))
const TextSettings = lazy(async () => ({
  default: (await import('./TextSettings.js')).TextSettings,
}))
const TextHistory = lazy(async () => ({ default: (await import('./TextHistory.js')).TextHistory }))
const AclEditor = lazy(async () => ({ default: (await import('./AclEditor.js')).AclEditor }))
const LoadDocumentSessions = async () => import('./DocumentSessions.js')
const DocumentSessions = lazy(async () => ({
  default: (await LoadDocumentSessions()).OwnDocumentSessions,
}))
const DocumentLaunchDialog = lazy(async () => ({
  default: (await LoadDocumentSessions()).DocumentLaunchDialog,
}))
const PreferencesKey = 'filebelt.appearance.v1'

interface Preferences {
  // oxlint-disable-next-line filebelt/pascal-case -- Existing `filebelt.appearance.v1` records persist this JSON key.
  density: Density
  // oxlint-disable-next-line filebelt/pascal-case -- Existing `filebelt.appearance.v1` records persist this JSON key.
  theme: ThemeChoice
}

const DefaultPreferences: Preferences = { density: 'comfortable', theme: 'system' }

function LoadPreferences(): Preferences {
  try {
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- This persisted browser record is validated field-by-field before use.
    const Value = JSON.parse(
      localStorage.getItem(PreferencesKey) ?? 'null',
    ) as Partial<Preferences> | null
    const Theme = Value?.theme
    const Density = Value?.density
    return {
      density:
        Density === 'compact' || Density === 'comfortable' ? Density : DefaultPreferences.density,
      theme:
        Theme === 'light' || Theme === 'dark' || Theme === 'system'
          ? Theme
          : DefaultPreferences.theme,
    }
  } catch {
    return DefaultPreferences
  }
}

const RoutePaths: Record<RouteId, string> = {
  drive: '/drive',
  'shared-drives': '/shared-drives',
  shared: '/shared',
  recent: '/recent',
  trash: '/trash',
  uploads: '/uploads',
  versions: '/versions',
  shares: '/shares',
  sessions: '/sessions',
  privacy: '/privacy',
  mcp: '/settings/mcp',
  mounts: '/settings/mounts',
  text: '/settings/text',
  markdown: '/markdown',
  documents: '/documents',
}

function RouteFromPath(Pathname: string): RouteId | 'admin' {
  if (Pathname === '/admin' || Pathname.startsWith('/admin/')) return 'admin'
  if (Pathname === '/settings/mcp' || Pathname.startsWith('/settings/mcp/')) return 'mcp'
  if (Pathname === '/settings/mounts') return 'mounts'
  if (Pathname === '/settings/text') return 'text'
  if (/^\/markdown\/[0-9a-f-]+$/i.test(Pathname)) return 'markdown'
  if (/^\/drive\/[0-9a-f-]+\/[0-9a-f-]+$/i.test(Pathname)) return 'drive'
  return (
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- Object.entries loses the exact keys of this closed RouteId mapping.
    (Object.entries(RoutePaths).find(([, Path]) => Pathname === Path)?.[0] as
      | RouteId
      | undefined) ?? 'drive'
  )
}

export type NavigationGuard = (Continue: () => void) => void

interface RouteLocation {
  Path: string
  Route: RouteId | 'admin'
}

interface FolderLocation {
  DriveId: string
  NodeId: string
}

function ParseFolderLocation(Pathname: string): FolderLocation | null {
  const Match = /^\/drive\/([0-9a-f-]+)\/([0-9a-f-]+)$/i.exec(Pathname)
  return Match?.[1] === undefined || Match[2] === undefined
    ? null
    : { DriveId: Match[1], NodeId: Match[2] }
}

function MarkdownReturnPath(): string {
  const State = window.history.state as unknown
  if (!IsNavigationState(State)) return RoutePaths.drive
  const Candidate = State.FileBeltReturnPath
  return typeof Candidate === 'string' && IsWorkspacePath(Candidate) ? Candidate : RoutePaths.drive
}

function IsNavigationState(Value: unknown): Value is { FileBeltReturnPath?: unknown } {
  return typeof Value === 'object' && Value !== null
}

function IsWorkspacePath(Pathname: string): boolean {
  return (
    Pathname === '/admin' ||
    Object.entries(RoutePaths).some(([Route, Path]) => Route !== 'markdown' && Pathname === Path) ||
    /^\/drive\/[0-9a-f-]+\/[0-9a-f-]+$/i.test(Pathname)
  )
}

function useRoute(
  DevelopmentMock: boolean,
): [
  RouteId | 'admin',
  (Route: RouteId | 'admin', OnNavigated?: () => void) => void,
  (EntryId: string) => void,
  (DriveId: string, NodeId: string) => void,
  (Guard: NavigationGuard | undefined) => void,
  string,
  () => void,
] {
  const [Location, SetLocation] = useState<RouteLocation>(() => ({
    Path: window.location.pathname,
    Route: RouteFromPath(window.location.pathname),
  }))
  const ActivePathReference = useRef(window.location.pathname)
  const GuardReference = useRef<NavigationGuard | undefined>(undefined)
  useEffect(() => {
    const OnPopState = (): void => {
      const NextPath = window.location.pathname
      const NextRoute = RouteFromPath(NextPath)
      const Guard = GuardReference.current
      if (Guard === undefined) {
        ActivePathReference.current = NextPath
        SetLocation({ Path: NextPath, Route: NextRoute })
        return
      }
      // The browser already changed history. Restore the active route until the
      // user chooses how to handle its unsaved source.
      window.history.pushState(
        {},
        '',
        InternalNavigationHref(ActivePathReference.current, DevelopmentMock),
      )
      Guard(() => {
        window.history.pushState({}, '', InternalNavigationHref(NextPath, DevelopmentMock))
        ActivePathReference.current = NextPath
        SetLocation({ Path: NextPath, Route: NextRoute })
      })
    }
    window.addEventListener('popstate', OnPopState)
    return () => {
      window.removeEventListener('popstate', OnPopState)
    }
  }, [DevelopmentMock])
  const Guarded = (Continue: () => void): void => {
    const Guard = GuardReference.current
    if (Guard === undefined) Continue()
    else Guard(Continue)
  }
  const Navigate = (Next: RouteId | 'admin', OnNavigated?: () => void): void => {
    Guarded(() => {
      const NextPath = Next === 'admin' ? '/admin' : RoutePaths[Next]
      window.history.pushState({}, '', InternalNavigationHref(NextPath, DevelopmentMock))
      ActivePathReference.current = NextPath
      SetLocation({ Path: NextPath, Route: Next })
      OnNavigated?.()
    })
  }
  const OpenMarkdown = (EntryId: string): void => {
    Guarded(() => {
      const NextPath = `/markdown/${EntryId}`
      const ReturnPath =
        Location.Route === 'markdown' ? MarkdownReturnPath() : ActivePathReference.current
      window.history.pushState(
        { FileBeltReturnPath: ReturnPath },
        '',
        InternalNavigationHref(NextPath, DevelopmentMock),
      )
      ActivePathReference.current = NextPath
      SetLocation({ Path: NextPath, Route: 'markdown' })
    })
  }
  const OpenFolder = (DriveId: string, NodeId: string): void => {
    Guarded(() => {
      const NextPath = `/drive/${DriveId}/${NodeId}`
      window.history.pushState({}, '', InternalNavigationHref(NextPath, DevelopmentMock))
      ActivePathReference.current = NextPath
      SetLocation({ Path: NextPath, Route: 'drive' })
    })
  }
  const ReturnToWorkspace = (): void => {
    Guarded(() => {
      const NextPath = MarkdownReturnPath()
      window.history.pushState({}, '', InternalNavigationHref(NextPath, DevelopmentMock))
      ActivePathReference.current = NextPath
      SetLocation({ Path: NextPath, Route: RouteFromPath(NextPath) })
    })
  }
  return [
    Location.Route,
    Navigate,
    OpenMarkdown,
    OpenFolder,
    (Guard: NavigationGuard | undefined) => {
      GuardReference.current = Guard
    },
    Location.Path,
    ReturnToWorkspace,
  ]
}

function SaveBlob(Blob: Blob, Name: string): void {
  const Url = URL.createObjectURL(Blob)
  const Anchor = document.createElement('a')
  Anchor.download = Name
  Anchor.href = Url
  Anchor.click()
  URL.revokeObjectURL(Url)
}

function RouteTitle(Route: RouteId | 'admin'): string {
  const Titles: Record<RouteId | 'admin', string> = {
    admin: En.admin,
    drive: En.myDrive,
    mcp: En.mcp,
    mounts: En.mounts,
    text: En.textEditing,
    markdown: En.markdown,
    documents: En.documentSessions,
    privacy: En.privacy,
    recent: En.recent,
    sessions: En.sessions,
    shared: En.shared,
    'shared-drives': En.sharedDrives,
    shares: En.shares,
    trash: En.trash,
    uploads: En.uploads,
    versions: En.versions,
  }
  return Titles[Route]
}

interface AppProps {
  Client: FileBeltClient
  DevelopmentMode?: boolean
  DocumentClient?: DocumentSessionClient
  McpClient?: McpSettingsClient
  MountClient?: MountSettingsClient
  NfsClient?: NfsAdminClient
  NfsTargetClient?: NfsTargetClient
}

export function OidcLoginHref(): string {
  return '/api/v1/auth/login?return_path=%2F'
}

export function SignInPrompt(): ReactNode {
  return (
    <section aria-labelledby='sign-in-heading' className='fb-loading'>
      <h1 id='sign-in-heading'>{En.signInRequired}</h1>
      <p>{En.signInDescription}</p>
      <Button appearance='primary' as='a' href={OidcLoginHref()}>
        {En.signIn}
      </Button>
    </section>
  )
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns the nested client props and this component only invokes their APIs.
export function App({
  Client,
  DevelopmentMode = false,
  DocumentClient,
  McpClient,
  MountClient,
  NfsClient,
  NfsTargetClient,
}: AppProps): ReactNode {
  const [
    Route,
    Navigate,
    OpenMarkdown,
    OpenFolder,
    SetNavigationGuard,
    RoutePath,
    ReturnToWorkspace,
  ] = useRoute(DevelopmentMode)
  const [Snapshot, SetSnapshot] = useState<WorkspaceSnapshot | null>(null)
  const [Selection, DispatchSelection] = useReducer(SelectionReducer, EmptySelection)
  const [Search, SetSearch] = useState('')
  const [Preferences, SetPreferences] = useState(LoadPreferences)
  const [Busy, SetBusy] = useState(false)
  const [ErrorMessage, SetError] = useState<string | null>(null)
  const [EntryBatchSummary, SetEntryBatchSummary] = useState<EntryMutationSummary | null>(null)
  const [AuthenticationRequired, SetAuthenticationRequired] = useState(false)
  const [Announcement, SetAnnouncement] = useState('')
  const [ActionEntryId, SetActionEntryId] = useState<string | null>(null)
  const [AclEntryId, SetAclEntryId] = useState<string | null>(null)
  const [RouteEntryId, SetRouteEntryId] = useState<string | null>(null)
  const [NavigationOpen, SetNavigationOpen] = useState(false)
  const [DocumentEntry, SetDocumentEntry] = useState<FileEntry | null>(null)
  const FileInput = useRef<HTMLInputElement>(null)
  const NavigationPanel = useRef<HTMLElement>(null)
  const WorkspaceScope = useMemo<WorkspaceLoadScope>(() => {
    if (Route !== 'drive') return { Kind: 'global' }
    const Folder = ParseFolderLocation(RoutePath)
    return {
      DriveId: Folder?.DriveId ?? null,
      Kind: 'folder',
      NodeId: Folder?.NodeId ?? null,
    }
  }, [Route, RoutePath])

  const HandleFailure = useCallback((Cause: unknown): void => {
    if (Cause instanceof AuthenticationRequiredError) {
      SetAuthenticationRequired(true)
      SetSnapshot(null)
      SetError(null)
      return
    }
    SetError(Cause instanceof Error ? Cause.message : En.offline)
  }, [])

  const Refresh = useCallback(
    async (Signal?: Readonly<AbortSignal>): Promise<void> => {
      try {
        SetError(null)
        SetSnapshot(await Client.GetWorkspace(Signal, WorkspaceScope))
        SetAuthenticationRequired(false)
      } catch (Cause) {
        if (!(Cause instanceof DOMException && Cause.name === 'AbortError')) HandleFailure(Cause)
      }
    },
    [Client, HandleFailure, WorkspaceScope],
  )

  useEffect(() => {
    const Controller = new AbortController()
    void Refresh(Controller.signal)
    return () => {
      Controller.abort()
    }
  }, [Refresh])

  useEffect(() => {
    localStorage.setItem(PreferencesKey, JSON.stringify(Preferences))
  }, [Preferences])

  useEffect(() => {
    SetAnnouncement(En.selectedAnnouncement(Selection.SelectedIds.size))
  }, [Selection.SelectedIds])

  useEffect(() => {
    if (!NavigationOpen) return undefined
    NavigationPanel.current?.querySelector<HTMLButtonElement>('button')?.focus()
    // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The browser owns and dispatches this platform KeyboardEvent object.
    const OnKeyDown = (Event: Readonly<KeyboardEvent>): void => {
      if (Event.key !== 'Escape') return
      Event.preventDefault()
      SetNavigationOpen(false)
      document.querySelector<HTMLButtonElement>('#main-navigation-trigger')?.focus()
    }
    document.addEventListener('keydown', OnKeyDown)
    return () => {
      document.removeEventListener('keydown', OnKeyDown)
    }
  }, [NavigationOpen])

  useEffect(() => {
    DispatchSelection({ Type: 'clear' })
    SetActionEntryId(null)
    SetAclEntryId(null)
    SetEntryBatchSummary(null)
  }, [Route, RoutePath])

  const Mutate = async (Operation: () => Promise<void>, Message: string): Promise<void> => {
    SetBusy(true)
    SetError(null)
    SetEntryBatchSummary(null)
    try {
      await Operation()
      await Refresh()
      SetAnnouncement(Message)
    } catch (Cause) {
      HandleFailure(Cause)
    } finally {
      SetBusy(false)
    }
  }

  const MutateEntries = async (
    Operation: (EntryIds: readonly string[]) => Promise<readonly EntryMutationOutcome[]>,
    Targets: readonly Readonly<FileEntry>[],
    Action: 'restore' | 'trash',
  ): Promise<void> => {
    if (Targets.length === 0) return
    SetBusy(true)
    SetError(null)
    SetEntryBatchSummary(null)
    try {
      const Outcomes = await Operation(Targets.map(({ Id }) => Id))
      const Summary = SummarizeEntryMutations(Targets, Outcomes)
      SetEntryBatchSummary(Summary.Failures.length === 0 ? null : Summary)
      DispatchSelection({ Ids: Summary.Failures.map(({ EntryId }) => EntryId), Type: 'set' })
      await Refresh()
      SetAnnouncement(
        Action === 'restore'
          ? En.restoreBatchOutcome(Summary.Succeeded, Summary.Failures.length)
          : En.trashBatchOutcome(Summary.Succeeded, Summary.Failures.length),
      )
    } catch (Cause) {
      await Refresh()
      HandleFailure(Cause)
    } finally {
      SetBusy(false)
    }
  }

  const Entries = useMemo(() => {
    if (Snapshot === null) return []
    let Result = Snapshot.Entries
    const Folder = ParseFolderLocation(RoutePath)
    const Drive =
      Folder === null
        ? Snapshot.Drives.find(({ Kind }) => Kind === 'private')
        : Snapshot.Drives.find(({ Id }) => Id === Folder.DriveId)
    if (Route === 'trash') Result = Result.filter(({ Trashed }) => Trashed)
    else {
      Result = Result.filter(({ Trashed }) => !Trashed)
      if (Route === 'drive' && Drive !== undefined) {
        const ParentId = Folder?.NodeId ?? Drive.RootId
        Result = Result.filter(
          ({ DriveId, ParentId: EntryParentId }) =>
            DriveId === Drive.Id && EntryParentId === ParentId,
        )
      }
    }
    if (Route === 'shared')
      Result = Result.filter(({ Owner }) => Owner !== Snapshot.CurrentUser.DisplayName)
    if (Route === 'shared-drives') Result = Result.filter(({ Shared }) => Shared)
    if (Route === 'recent')
      Result = [...Result].sort((Left, Right) => Right.ModifiedAt.localeCompare(Left.ModifiedAt))
    const NormalizedSearch = Search.trim().toLocaleLowerCase()
    if (NormalizedSearch.length > 0)
      Result = Result.filter(({ Name }) => Name.toLocaleLowerCase().includes(NormalizedSearch))
    return Result
  }, [Route, RoutePath, Search, Snapshot])

  useEffect(() => {
    const VisibleIds = new Set(Entries.map(({ Id }) => Id))
    if ([...Selection.SelectedIds].some((Id) => !VisibleIds.has(Id)))
      DispatchSelection({ Type: 'clear' })
  }, [Entries, Selection.SelectedIds])

  const SelectedEntries = Snapshot?.Entries.filter(({ Id }) => Selection.SelectedIds.has(Id)) ?? []
  const PrimarySelection = SelectedEntries.at(-1)
  const RouteEntry = Snapshot?.Entries.find(({ Id }) => Id === RouteEntryId)
  const ActionEntry = Snapshot?.Entries.find(({ Id }) => Id === ActionEntryId)
  const AclEntry = Snapshot?.Entries.find(({ Id }) => Id === AclEntryId)
  const PrimaryFileActionDescription =
    PrimarySelection?.Kind === 'symlink' ? 'symlink-actions-unavailable' : undefined
  const ActionFileActionDescription =
    ActionEntry?.Kind === 'symlink' ? 'symlink-actions-unavailable' : undefined
  const MarkdownEntryId = Route === 'markdown' ? window.location.pathname.split('/')[2] : undefined
  const MarkdownEntry = Snapshot?.Entries.find(({ Id }) => Id === MarkdownEntryId)
  const FolderLocation = ParseFolderLocation(RoutePath)
  const CurrentDrive =
    Snapshot?.Drives.find(({ Id }) => Id === FolderLocation?.DriveId) ??
    Snapshot?.Drives.find(({ Kind }) => Kind === 'private')
  const CurrentFolder = Snapshot?.Entries.find(
    ({ DriveId, Id }) => DriveId === CurrentDrive?.Id && Id === FolderLocation?.NodeId,
  )
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The markdown package owns this reference value and the callback only observes it.
  const OpenFileBeltReference = (Target: FileBeltReference): boolean => {
    // Snapshot membership is a UX hint only; the destination read still obtains
    // a new server-authorized grant before rendering any content.
    const Entry = Snapshot?.Entries.find(({ Id }) => Id === Target.NodeId)
    if (
      Entry?.Kind !== 'file' ||
      Entry.DriveId !== Target.DriveId ||
      Entry.TextEligibility === 'ineligible' ||
      Entry.TextEligibility === 'history-only'
    )
      return false
    OpenMarkdown(Target.NodeId)
    return true
  }

  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns and supplies this mutable file-input event object.
  const OnFiles = (Event: ChangeEvent<HTMLInputElement>): void => {
    const Candidates = [...(Event.currentTarget.files ?? [])].map((File) => ({
      Data: File,
      ...(File.type.length === 0 ? {} : { MediaType: File.type }),
      Name: File.name,
      Size: File.size,
    }))
    Event.currentTarget.value = ''
    if (Candidates.length > 0)
      void Mutate(
        async () =>
          Client.Upload(
            Candidates,
            CurrentDrive === undefined || CurrentFolder === undefined
              ? undefined
              : { DriveId: CurrentDrive.Id, ParentId: CurrentFolder.Id },
          ),
        En.uploadCompleted(Candidates.length),
      )
  }

  const DownloadEntry = async (Entry: Readonly<FileEntry>): Promise<void> => {
    if (Entry.Kind !== 'file') return
    SetBusy(true)
    try {
      SaveBlob(await Client.Download(Entry.Id), Entry.Name)
      SetAnnouncement(En.downloadStarted(Entry.Name))
    } catch (Cause) {
      HandleFailure(Cause)
    } finally {
      SetBusy(false)
    }
  }

  const ImportOfficeEntry = async (Entry: Readonly<FileEntry>): Promise<void> => {
    if (Entry.Kind !== 'file' || Entry.HeadVersionId === null || !IsOfficeImportCandidate(Entry))
      return
    const TargetName = MarkdownImportName(Entry.Name)
    const HeadVersionId = Entry.HeadVersionId
    await Mutate(async () => {
      const Markdown = await import('@filebelt/markdown')
      const SourceType = Markdown.OfficeImportType(Entry.Name)
      if (SourceType === null) throw new Error(En.markdownImportUnavailable)
      const Source = await Client.ReadMarkdown(Entry.Id, HeadVersionId)
      const Contents = new Uint8Array(await Source.arrayBuffer())
      const Converted = await Markdown.ImportOfficeMarkdown({ Contents, SourceType })
      await Client.ImportMarkdown({
        Contents: new Blob([Converted], { type: 'text/markdown' }),
        EntryId: Entry.Id,
        SourceVersionId: HeadVersionId,
        TargetName,
      })
    }, En.markdownImportCompleted(TargetName))
  }

  const ChangePreference = (Patch: Partial<Preferences>): void => {
    SetPreferences((Current) => ({ ...Current, ...Patch }))
  }
  const PreloadDocuments = (): void => {
    void LoadDocumentSessions()
  }

  const Navigation: ReadonlyArray<{ Icon: typeof Files; Id: RouteId | 'admin'; Label: string }> = [
    { Icon: Files, Id: 'drive', Label: En.myDrive },
    { Icon: HardDrive, Id: 'shared-drives', Label: En.sharedDrives },
    { Icon: Users, Id: 'shared', Label: En.shared },
    { Icon: Clock3, Id: 'recent', Label: En.recent },
    { Icon: Trash2, Id: 'trash', Label: En.trash },
    { Icon: CloudUpload, Id: 'uploads', Label: En.uploads },
    { Icon: History, Id: 'versions', Label: En.versions },
    { Icon: Link2, Id: 'shares', Label: En.shares },
    { Icon: ShieldCheck, Id: 'sessions', Label: En.sessions },
    { Icon: Bell, Id: 'privacy', Label: En.privacy },
    { Icon: ServerCog, Id: 'mcp', Label: En.mcp },
    { Icon: Network, Id: 'mounts', Label: En.mounts },
    { Icon: FilePenLine, Id: 'text', Label: En.textEditing },
    ...(DocumentClient === undefined
      ? []
      : [{ Icon: FilePenLine, Id: 'documents' as const, Label: En.documentSessions }]),
    ...(Snapshot?.CurrentUser.IsTenantAdmin === true
      ? [{ Icon: Settings2, Id: 'admin' as const, Label: En.admin }]
      : []),
  ]

  return (
    <FileBeltProvider Density={Preferences.density} ThemeChoice={Preferences.theme}>
      <div className={DevelopmentMode ? 'fb-app-shell is-development' : 'fb-app-shell'}>
        <a className='fb-skip-link' href='#main-content'>
          {En.skipToContent}
        </a>
        <header className='fb-topbar'>
          <Button
            aria-controls='main-navigation'
            aria-expanded={NavigationOpen}
            aria-label={En.mainNavigation}
            appearance='subtle'
            className='fb-mobile-menu'
            id='main-navigation-trigger'
            icon={<MenuIcon />}
            onClick={() => {
              SetNavigationOpen((Open) => !Open)
            }}
          />
          <button
            className='fb-brand'
            onClick={() => {
              SetRouteEntryId(null)
              Navigate('drive')
            }}
            type='button'
          >
            <BrandMark />
            <span>{En.appName}</span>
          </button>
          <Input
            className='fb-search'
            contentBefore={<SearchIcon aria-hidden='true' size={18} strokeWidth={1.75} />}
            onChange={(Ignored, Data) => {
              SetSearch(Data.value)
            }}
            placeholder={En.search}
            type='search'
            value={Search}
          />
          <Menu>
            <MenuTrigger disableButtonEnhancement>
              <Button aria-label={En.userMenu} appearance='subtle'>
                <span className='fb-avatar' aria-hidden='true'>
                  AM
                </span>
                <span className='fb-user-name'>
                  {Snapshot?.CurrentUser.DisplayName ?? En.account}
                </span>
              </Button>
            </MenuTrigger>
            <MenuPopover>
              <MenuList>
                <MenuItem disabled>{En.theme}</MenuItem>
                <MenuItem
                  icon={<Settings2 />}
                  onClick={() => {
                    ChangePreference({ theme: 'system' })
                  }}
                >
                  {En.system}
                </MenuItem>
                <MenuItem
                  icon={<Sun />}
                  onClick={() => {
                    ChangePreference({ theme: 'light' })
                  }}
                >
                  {En.light}
                </MenuItem>
                <MenuItem
                  icon={<Moon />}
                  onClick={() => {
                    ChangePreference({ theme: 'dark' })
                  }}
                >
                  {En.dark}
                </MenuItem>
                <MenuItem disabled>{En.viewSettings}</MenuItem>
                <MenuItem
                  onClick={() => {
                    ChangePreference({ density: 'comfortable' })
                  }}
                >
                  {En.comfortable}
                </MenuItem>
                <MenuItem
                  onClick={() => {
                    ChangePreference({ density: 'compact' })
                  }}
                >
                  {En.compact}
                </MenuItem>
              </MenuList>
            </MenuPopover>
          </Menu>
        </header>

        {DevelopmentMode ? (
          <div className='fb-development-banner' role='status'>
            {En.developmentMock}
          </div>
        ) : null}

        <nav
          aria-label={En.mainNavigation}
          className={NavigationOpen ? 'fb-navigation is-open' : 'fb-navigation'}
          id='main-navigation'
          ref={NavigationPanel}
        >
          {Navigation.map((Item) => (
            <button
              aria-current={Route === Item.Id ? 'page' : undefined}
              className={Route === Item.Id ? 'fb-nav-item is-active' : 'fb-nav-item'}
              key={Item.Id}
              onClick={() => {
                SetRouteEntryId(null)
                Navigate(Item.Id, () => {
                  SetNavigationOpen(false)
                  requestAnimationFrame(() => {
                    document.querySelector<HTMLElement>('#main-content')?.focus()
                  })
                })
              }}
              type='button'
            >
              <FileBeltIcon Icon={Item.Icon} />
              <span>{Item.Label}</span>
            </button>
          ))}
        </nav>

        <main className='fb-main' id='main-content' tabIndex={-1}>
          {ErrorMessage === null ? null : (
            <div className='fb-error' role='alert'>
              <span>{ErrorMessage}</span>
              <Button appearance='transparent' onClick={() => void Refresh()}>
                {En.refresh}
              </Button>
            </div>
          )}
          {EntryBatchSummary === null ? null : (
            <div className='fb-batch-error fb-error' role='alert'>
              <div>
                <strong>{En.entryBatchFailures(EntryBatchSummary.Failures.length)}</strong>
                <ul>
                  {EntryBatchSummary.Failures.map((Failure) => (
                    <li key={Failure.EntryId}>
                      <BidiText>{Failure.Name}</BidiText>: {EntryMutationErrorText(Failure.Error)}
                    </li>
                  ))}
                </ul>
              </div>
              <Button
                appearance='transparent'
                onClick={() => {
                  SetEntryBatchSummary(null)
                }}
              >
                {En.close}
              </Button>
            </div>
          )}
          {AuthenticationRequired ? (
            <SignInPrompt />
          ) : Snapshot === null ? (
            <div className='fb-loading'>
              <Spinner label={En.loading} />
            </div>
          ) : (
            <>
              {Route === 'admin' && Snapshot.CurrentUser.IsTenantAdmin ? (
                <Suspense fallback={<Spinner label={En.loading} />}>
                  <AdminPanel
                    Drives={Snapshot.Admin.Drives}
                    Groups={Snapshot.Admin.Groups}
                    OnCreateGroup={async (Name) =>
                      Mutate(async () => Client.CreateGroup(Name), En.createdGroup(Name))
                    }
                    OnCreateSharedDrive={async (Name) =>
                      Mutate(
                        async () => Client.CreateSharedDrive(Name),
                        En.createdSharedDrive(Name),
                      )
                    }
                    OnToggleUserSuspension={async (Id) =>
                      Mutate(async () => Client.SuspendUser(Id), En.userStatusUpdated)
                    }
                    {...(NfsClient === undefined ? {} : { NfsClient })}
                    Users={Snapshot.Admin.Users}
                  />
                </Suspense>
              ) : null}
              {Route === 'admin' && !Snapshot.CurrentUser.IsTenantAdmin ? (
                <div className='fb-error' role='alert'>
                  {En.permissionDenied}
                </div>
              ) : null}
              {Route === 'uploads' ? <UploadsView Strings={En} Uploads={Snapshot.Uploads} /> : null}
              {Route === 'versions' && RouteEntry?.Kind === 'file' ? (
                <Suspense fallback={<Spinner label={En.loading} />}>
                  <TextHistory
                    Client={Client}
                    Entry={RouteEntry}
                    OnRestore={async (Id) =>
                      Mutate(async () => Client.RestoreVersion(Id), En.versionRestored)
                    }
                  />
                </Suspense>
              ) : null}
              {Route === 'versions' && RouteEntry?.Kind !== 'file' ? (
                <VersionsView
                  File={undefined}
                  OnRestore={async (Id) =>
                    Mutate(async () => Client.RestoreVersion(Id), En.versionRestored)
                  }
                  Strings={En}
                  Versions={Snapshot.Versions}
                />
              ) : null}
              {Route === 'shares' ? (
                <SharesView
                  File={RouteEntry}
                  OnCreate={async (Input) =>
                    Mutate(async () => Client.CreateShare(Input), En.shareCreated)
                  }
                  OnRevoke={async (Id) =>
                    Mutate(async () => Client.RevokeShare(Id), En.shareRevoked)
                  }
                  Shares={Snapshot.Shares}
                  Strings={En}
                />
              ) : null}
              {Route === 'sessions' ? (
                <SessionsView
                  OnRevoke={async (Id) =>
                    Mutate(async () => Client.RevokeSession(Id), En.sessionRevoked)
                  }
                  Sessions={Snapshot.Sessions}
                  Strings={En}
                />
              ) : null}
              {Route === 'documents' && DocumentClient !== undefined ? (
                <Suspense fallback={<Spinner label={En.documentSessions} />}>
                  <DocumentSessions Client={DocumentClient} OnWorkspaceChanged={Refresh} />
                </Suspense>
              ) : null}
              {Route === 'documents' && DocumentClient === undefined ? (
                <div className='fb-error' role='alert'>
                  {En.documentEditorUnavailable}
                </div>
              ) : null}
              {Route === 'privacy' ? (
                <PrivacyView
                  Events={Snapshot.Privacy}
                  OnMarkRead={async () =>
                    Mutate(async () => Client.MarkPrivacyRead(), En.privacyRead)
                  }
                  Strings={En}
                />
              ) : null}
              {Route === 'mcp' && McpClient !== undefined ? (
                <Suspense fallback={<Spinner label={En.loading} />}>
                  <McpSettings
                    Client={McpClient}
                    IsTenantAdmin={Snapshot.CurrentUser.IsTenantAdmin}
                  />
                </Suspense>
              ) : null}
              {Route === 'mcp' && McpClient === undefined ? (
                <div className='fb-error' role='alert'>
                  MCP settings are unavailable.
                </div>
              ) : null}
              {Route === 'mounts' && MountClient !== undefined ? (
                <Suspense fallback={<Spinner label={En.loading} />}>
                  <MountSettings Client={MountClient} NfsClient={NfsTargetClient} />
                </Suspense>
              ) : null}
              {Route === 'mounts' && MountClient === undefined ? (
                <div className='fb-error' role='alert'>
                  Mount settings are unavailable.
                </div>
              ) : null}
              {Route === 'text' ? (
                <Suspense fallback={<Spinner label={En.loading} />}>
                  <TextSettings Client={Client} />
                </Suspense>
              ) : null}
              {Route === 'markdown' &&
              MarkdownEntry?.Kind === 'file' &&
              MarkdownEntry.TextEligibility !== 'ineligible' &&
              MarkdownEntry.TextEligibility !== 'history-only' ? (
                <Suspense fallback={<Spinner label={En.markdownLoading} />}>
                  <MarkdownFileView
                    Client={Client}
                    Entry={MarkdownEntry}
                    {...(McpClient === undefined ? {} : { McpClient })}
                    OnClose={() => {
                      ReturnToWorkspace()
                    }}
                    OnFileBeltLink={OpenFileBeltReference}
                    OnNavigationGuardChange={SetNavigationGuard}
                    OnSaved={() => void Refresh()}
                  />
                </Suspense>
              ) : null}
              {Route === 'markdown' &&
              (MarkdownEntry === undefined ||
                MarkdownEntry.Kind !== 'file' ||
                MarkdownEntry.TextEligibility === 'ineligible' ||
                MarkdownEntry.TextEligibility === 'history-only') ? (
                <div className='fb-error' role='alert'>
                  {En.markdownUnavailable}
                </div>
              ) : null}
              {['drive', 'shared-drives', 'shared', 'recent', 'trash'].includes(Route) ? (
                <section aria-labelledby='files-heading' className='fb-files-view'>
                  <header className='fb-page-heading'>
                    <div>
                      <p className='fb-eyebrow'>{En.files}</p>
                      <h1 id='files-heading'>
                        {Route === 'drive'
                          ? (CurrentFolder?.Name ?? CurrentDrive?.Name ?? RouteTitle(Route))
                          : RouteTitle(Route)}
                      </h1>
                    </div>
                    <div className='fb-heading-actions'>
                      <Tooltip content={En.refresh} relationship='label'>
                        <Button
                          aria-label={En.refresh}
                          appearance='subtle'
                          className='fb-interactive-button'
                          icon={<RefreshCw />}
                          onClick={() => void Refresh()}
                        />
                      </Tooltip>
                      <Button
                        appearance='primary'
                        icon={<Upload />}
                        onClick={() => FileInput.current?.click()}
                      >
                        {En.upload}
                      </Button>
                      <input
                        accept='*/*'
                        aria-label={En.uploadHint}
                        hidden
                        multiple
                        onChange={OnFiles}
                        ref={FileInput}
                        type='file'
                      />
                    </div>
                  </header>
                  {Route === 'drive' && CurrentFolder !== undefined ? (
                    <Button
                      appearance='subtle'
                      icon={<ArrowLeft />}
                      onClick={() => {
                        if (CurrentDrive === undefined) return
                        const ParentId = CurrentFolder.ParentId
                        if (
                          ParentId === undefined ||
                          ParentId === null ||
                          ParentId === CurrentDrive.RootId
                        )
                          Navigate('drive')
                        else OpenFolder(CurrentDrive.Id, ParentId)
                      }}
                    >
                      {En.folderBack}
                    </Button>
                  ) : null}
                  <div aria-label={En.fileCommands} className='fb-commandbar' role='toolbar'>
                    <span>{En.selectedAnnouncement(Selection.SelectedIds.size)}</span>
                    <Button
                      aria-describedby={PrimaryFileActionDescription}
                      disabled={PrimarySelection?.Kind !== 'file' || Busy}
                      icon={<Download />}
                      onClick={() =>
                        PrimarySelection === undefined
                          ? undefined
                          : void DownloadEntry(PrimarySelection)
                      }
                    >
                      {En.download}
                    </Button>
                    <Button
                      disabled={SelectedEntries.length === 0 || Busy}
                      icon={Route === 'trash' ? <FolderInput /> : <Trash2 />}
                      onClick={() => {
                        const Restoring = Route === 'trash'
                        void MutateEntries(
                          Restoring
                            ? async (EntryIds) => Client.RestoreEntries(EntryIds)
                            : async (EntryIds) => Client.TrashEntries(EntryIds),
                          SelectedEntries,
                          Restoring ? 'restore' : 'trash',
                        )
                      }}
                    >
                      {Route === 'trash' ? En.restore : En.moveToTrash}
                    </Button>
                    <Button
                      aria-describedby={PrimaryFileActionDescription}
                      disabled={PrimarySelection?.Kind !== 'file'}
                      icon={<History />}
                      onClick={() => {
                        if (PrimarySelection !== undefined) SetRouteEntryId(PrimarySelection.Id)
                        Navigate('versions')
                      }}
                    >
                      {En.versions}
                    </Button>
                    <Button
                      disabled={PrimarySelection === undefined}
                      icon={<Link2 />}
                      onClick={() => {
                        if (PrimarySelection !== undefined) SetRouteEntryId(PrimarySelection.Id)
                        Navigate('shares')
                      }}
                    >
                      {En.shares}
                    </Button>
                    <Button
                      disabled={
                        SelectedEntries.length !== 1 ||
                        PrimarySelection?.Kind === 'symlink' ||
                        PrimarySelection?.DriveId === undefined
                      }
                      icon={<ShieldCheck />}
                      onClick={() => {
                        if (PrimarySelection !== undefined) SetAclEntryId(PrimarySelection.Id)
                      }}
                    >
                      {En.manageAccess}
                    </Button>
                    <Button
                      aria-describedby={PrimaryFileActionDescription}
                      disabled={
                        PrimarySelection === undefined ||
                        PrimarySelection.TextEligibility === 'ineligible' ||
                        PrimarySelection.TextEligibility === 'history-only'
                      }
                      icon={<FilePenLine />}
                      onClick={() => {
                        if (PrimarySelection !== undefined) OpenMarkdown(PrimarySelection.Id)
                      }}
                    >
                      {En.openMarkdown}
                    </Button>
                    <Button
                      aria-describedby={PrimaryFileActionDescription}
                      disabled={
                        PrimarySelection === undefined ||
                        !IsOfficeImportCandidate(PrimarySelection) ||
                        Busy
                      }
                      icon={<FileOutput />}
                      onClick={() =>
                        PrimarySelection === undefined
                          ? undefined
                          : void ImportOfficeEntry(PrimarySelection)
                      }
                    >
                      {En.importMarkdown}
                    </Button>
                    {DocumentClient === undefined ? null : (
                      <Button
                        aria-describedby={PrimaryFileActionDescription}
                        disabled={
                          PrimarySelection === undefined ||
                          !IsOfficeDocumentCandidate(PrimarySelection) ||
                          Busy
                        }
                        icon={<FilePenLine />}
                        onFocus={PreloadDocuments}
                        onMouseEnter={PreloadDocuments}
                        onClick={() => {
                          if (PrimarySelection !== undefined) SetDocumentEntry(PrimarySelection)
                        }}
                      >
                        {En.documentEditor}
                      </Button>
                    )}
                  </div>
                  <div className='fb-content-split'>
                    <FileTable
                      DispatchSelection={DispatchSelection}
                      Entries={Entries}
                      OnOpenActions={(Entry) => {
                        DispatchSelection({ Id: Entry.Id, Type: 'replace' })
                        SetActionEntryId(Entry.Id)
                      }}
                      OnOpenEntry={(Entry) => {
                        if (Entry.Kind === 'folder' && Entry.DriveId !== undefined)
                          OpenFolder(Entry.DriveId, Entry.Id)
                        else if (
                          Entry.Kind === 'file' &&
                          Entry.TextEligibility !== 'ineligible' &&
                          Entry.TextEligibility !== 'history-only'
                        )
                          OpenMarkdown(Entry.Id)
                        else SetActionEntryId(Entry.Id)
                      }}
                      Selection={Selection}
                      Strings={En}
                    />
                    <aside aria-label={En.details} className='fb-details-pane'>
                      {PrimarySelection === undefined ? (
                        <p className='fb-muted'>{En.noSelection}</p>
                      ) : (
                        <>
                          <div className='fb-details-icon'>
                            <FileBeltIcon
                              Icon={
                                PrimarySelection.Kind === 'folder'
                                  ? FolderClock
                                  : PrimarySelection.Kind === 'symlink'
                                    ? FileSymlink
                                    : Files
                              }
                              {...(PrimarySelection.Kind === 'symlink'
                                ? { Label: En.symlink }
                                : {})}
                              size={28}
                            />
                          </div>
                          <h2>
                            <BidiText>{PrimarySelection.Name}</BidiText>
                          </h2>
                          <dl>
                            <div>
                              <dt>{En.owner}</dt>
                              <dd>
                                <BidiText>{PrimarySelection.Owner}</BidiText>
                              </dd>
                            </div>
                            <div>
                              <dt>{En.version}</dt>
                              <dd>
                                {PrimarySelection.Kind === 'file' ? PrimarySelection.Version : '—'}
                              </dd>
                            </div>
                            <div>
                              <dt>{En.status}</dt>
                              <dd>
                                {PrimarySelection.Status === 'ready' ? (
                                  <StatusPill Kind='success'>{En.ready}</StatusPill>
                                ) : null}
                                {PrimarySelection.Status === 'uploading' ? (
                                  <StatusPill Kind='informative'>{En.uploading}</StatusPill>
                                ) : null}
                                {PrimarySelection.Status === 'conflict' ? (
                                  <StatusPill Kind='warning'>
                                    <FileBeltIcon Icon={AlertTriangle} size={16} /> {En.conflict}
                                  </StatusPill>
                                ) : null}
                                {PrimarySelection.Status === 'quarantined' ? (
                                  <StatusPill Kind='danger'>
                                    <FileBeltIcon Icon={LockKeyhole} size={16} /> {En.quarantined}
                                  </StatusPill>
                                ) : null}
                              </dd>
                            </div>
                          </dl>
                          {PrimarySelection.Kind === 'symlink' ? (
                            <p className='fb-muted' id='symlink-actions-unavailable'>
                              {En.symlinkActionsUnavailable}
                            </p>
                          ) : null}
                          <Button
                            appearance='secondary'
                            icon={<MoreHorizontal />}
                            onClick={() => {
                              SetActionEntryId(PrimarySelection.Id)
                            }}
                          >
                            {En.openMenu}
                          </Button>
                        </>
                      )}
                    </aside>
                  </div>
                </section>
              ) : null}
            </>
          )}
        </main>
        {Busy ? (
          <div className='fb-working' role='status'>
            <Spinner size='tiny' />
            <span>{En.working}</span>
          </div>
        ) : null}
        <div aria-atomic='true' aria-live='polite' style={VisuallyHiddenStyle}>
          {Announcement}
        </div>
        {ActionEntry === undefined ? null : (
          <Dialog
            modalType='modal'
            onOpenChange={(IgnoredEvent, Data) => {
              void IgnoredEvent
              if (!Data.open) SetActionEntryId(null)
            }}
            open
          >
            <DialogSurface aria-describedby={undefined}>
              <DialogBody>
                <DialogTitle>
                  <BidiText>{ActionEntry.Name}</BidiText>
                </DialogTitle>
                <DialogContent className='fb-action-menu'>
                  <Button
                    appearance='subtle'
                    aria-describedby={ActionFileActionDescription}
                    disabled={
                      ActionEntry.TextEligibility === 'ineligible' ||
                      ActionEntry.TextEligibility === 'history-only'
                    }
                    icon={<FilePenLine />}
                    onClick={() => {
                      SetActionEntryId(null)
                      OpenMarkdown(ActionEntry.Id)
                    }}
                  >
                    {En.openMarkdown}
                  </Button>
                  <Button
                    appearance='subtle'
                    aria-describedby={ActionFileActionDescription}
                    disabled={ActionEntry.Kind !== 'file'}
                    icon={<Download />}
                    onClick={() => {
                      SetActionEntryId(null)
                      void DownloadEntry(ActionEntry)
                    }}
                  >
                    {En.download}
                  </Button>
                  <Button
                    appearance='subtle'
                    aria-describedby={ActionFileActionDescription}
                    disabled={!IsOfficeImportCandidate(ActionEntry) || Busy}
                    icon={<FileOutput />}
                    onClick={() => {
                      SetActionEntryId(null)
                      void ImportOfficeEntry(ActionEntry)
                    }}
                  >
                    {En.importMarkdown}
                  </Button>
                  {DocumentClient === undefined ? null : (
                    <Button
                      appearance='subtle'
                      aria-describedby={ActionFileActionDescription}
                      disabled={!IsOfficeDocumentCandidate(ActionEntry) || Busy}
                      icon={<FilePenLine />}
                      onFocus={PreloadDocuments}
                      onMouseEnter={PreloadDocuments}
                      onClick={() => {
                        SetActionEntryId(null)
                        SetDocumentEntry(ActionEntry)
                      }}
                    >
                      {En.documentEditor}
                    </Button>
                  )}
                  <Button
                    appearance='subtle'
                    icon={<Link2 />}
                    onClick={() => {
                      SetActionEntryId(null)
                      SetRouteEntryId(ActionEntry.Id)
                      Navigate('shares')
                    }}
                  >
                    {En.shares}
                  </Button>
                  <Button
                    appearance='subtle'
                    disabled={ActionEntry.Kind === 'symlink' || ActionEntry.DriveId === undefined}
                    icon={<ShieldCheck />}
                    onClick={() => {
                      SetActionEntryId(null)
                      SetAclEntryId(ActionEntry.Id)
                    }}
                  >
                    {En.manageAccess}
                  </Button>
                  <Button
                    appearance='subtle'
                    icon={ActionEntry.Trashed ? <FolderInput /> : <Trash2 />}
                    onClick={() => {
                      SetActionEntryId(null)
                      void MutateEntries(
                        ActionEntry.Trashed
                          ? async (EntryIds) => Client.RestoreEntries(EntryIds)
                          : async (EntryIds) => Client.TrashEntries(EntryIds),
                        [ActionEntry],
                        ActionEntry.Trashed ? 'restore' : 'trash',
                      )
                    }}
                  >
                    {ActionEntry.Trashed ? En.restore : En.moveToTrash}
                  </Button>
                </DialogContent>
                <DialogActions>
                  <Button
                    appearance='secondary'
                    onClick={() => {
                      SetActionEntryId(null)
                    }}
                  >
                    {En.close}
                  </Button>
                </DialogActions>
              </DialogBody>
            </DialogSurface>
          </Dialog>
        )}
        {AclEntry === undefined ? null : (
          <Suspense fallback={null}>
            <AclEditor
              Client={Client}
              Entry={AclEntry}
              OnClose={() => {
                SetAclEntryId(null)
              }}
              OnSaved={() => {
                SetAnnouncement(En.aclSaved)
              }}
            />
          </Suspense>
        )}
        {DocumentClient === undefined || DocumentEntry === null ? null : (
          <Suspense fallback={null}>
            <DocumentLaunchDialog
              Client={DocumentClient}
              Entry={DocumentEntry}
              OnClose={() => {
                SetDocumentEntry(null)
              }}
              OnCreated={() => {
                SetAnnouncement(En.documentSessionCreated)
              }}
            />
          </Suspense>
        )}
      </div>
    </FileBeltProvider>
  )
}

function IsOfficeImportCandidate(Entry: Readonly<FileEntry>): boolean {
  return (
    Entry.Kind === 'file' &&
    Entry.HeadVersionId !== null &&
    Entry.Size !== null &&
    Entry.Size <= 8 * 1024 * 1024 &&
    /\.(?:csv|docx|odp|ods|odt|pptx|rtf|xlsx)$/i.test(Entry.Name)
  )
}

function MarkdownImportName(Name: string): string {
  return `${Name.replace(/\.[^.]+$/, '') || 'Imported document'}.md`
}
