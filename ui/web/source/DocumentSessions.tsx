// SPDX-License-Identifier: Apache-2.0

import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Select,
  Spinner,
} from "@fluentui/react-components";
import { FileWarning, MonitorCog, UserRoundCheck } from "lucide-react";
import { useCallback, useEffect, useId, useState } from "react";
import type { ReactNode, SyntheticEvent } from "react";

import { BidiText, FileBeltIcon, StatusPill } from "@filebelt/design-system";

import type { FileEntry } from "./model.js";
import type { components } from "./generated/openapi.js";
import type {
  DocumentSessionClient,
  DocumentSessionDetail,
  DocumentSessionLaunchHandoff,
  DocumentSessionMode,
} from "./document-http-client.js";
import { IsOfficeDocumentCandidate } from "./document-eligibility.js";
import { En } from "./strings.js";
export { IsOfficeDocumentCandidate } from "./document-eligibility.js";

interface DocumentLaunchDialogProps {
  Client: DocumentSessionClient;
  Entry: FileEntry | null;
  OnClose(): void;
  OnCreated(Detail: DocumentSessionDetail): void;
}

interface PreparedDocumentLaunch {
  readonly ProviderOrigin: string;
  readonly SessionId: string;
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns nested props and lifecycle callbacks are receiver-free parent functions.
export function DocumentLaunchDialog({
  Client,
  Entry,
  OnClose,
  OnCreated,
}: DocumentLaunchDialogProps): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const [Mode, SetMode] = useState<DocumentSessionMode>("view");
  const [Busy, SetBusy] = useState(false);
  const [ErrorMessage, SetErrorMessage] = useState<string | null>(null);
  const [PreparedLaunch, SetPreparedLaunch] = useState<PreparedDocumentLaunch | null>(null);

  useEffect(() => {
    SetPreparedLaunch(null);
  }, [Entry]);
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns and supplies the synthetic submit event contract.
  const Submit = async (Event: Readonly<SyntheticEvent<HTMLFormElement>>): Promise<void> => {
    Event.preventDefault();
    SetBusy(true);
    SetErrorMessage(null);
    try {
      if (PreparedLaunch !== null) {
        // A fresh grant is intentionally held only in this stack frame, then
        // immediately submitted. Closing or waiting on consent leaves no raw
        // grant in React state or browser storage.
        SubmitDocumentLaunch(await Client.redeemLaunch(PreparedLaunch.SessionId));
        return;
      }
      if (
        Entry?.DriveId === undefined ||
        !IsOfficeDocumentCandidate(Entry) ||
        Entry.HeadVersionId === null
      )
        return;
      const Detail = await Client.createSession({
        BaseVersionId: Entry.HeadVersionId,
        DriveId: Entry.DriveId,
        Mode,
        NodeId: Entry.Id,
      });
      OnCreated(Detail);
      SetPreparedLaunch({ ProviderOrigin: Detail.provider_origin, SessionId: Detail.session.id });
    } catch (Cause) {
      SetErrorMessage(Cause instanceof Error ? Cause.message : En.offline);
    } finally {
      SetBusy(false);
    }
  };

  return (
    <Dialog
      modalType="modal"
      open={Entry !== null}
      onOpenChange={(Ignored, Data) => {
        if (!Data.open) OnClose();
      }}
    >
      <DialogSurface className="fb-document-dialog">
        <form onSubmit={(Event) => void Submit(Event)}>
          <DialogBody>
            <DialogTitle>
              {PreparedLaunch === null ? En.documentEditor : En.documentConsent}
            </DialogTitle>
            <DialogContent>
              {Entry === null ? null : (
                <p>
                  <BidiText>{Entry.Name}</BidiText>
                </p>
              )}
              {PreparedLaunch === null ? (
                <p className="fb-muted">{En.documentPreparing}</p>
              ) : (
                <dl className="fb-document-disclosures">
                  <div>
                    <dt>{En.documentProvider}</dt>
                    <dd>{PreparedLaunch.ProviderOrigin}</dd>
                  </div>
                  <div>
                    <dt>{En.documentMode}</dt>
                    <dd>{ModeLabel(Mode)}</dd>
                  </div>
                  <div>
                    <dt>{En.documentSource}</dt>
                    <dd>{En.documentConsentSource}</dd>
                  </div>
                  <div>
                    <dt>{En.documentCollaborators}</dt>
                    <dd>{En.documentConsentCollaborators}</dd>
                  </div>
                  <div>
                    <dt>{En.documentExport}</dt>
                    <dd>{En.documentConsentExport}</dd>
                  </div>
                </dl>
              )}
              <label className="fb-document-mode">
                {En.documentMode}
                <Select
                  disabled={Busy || PreparedLaunch !== null}
                  onChange={(Event) => {
                    const Value = Event.target.value;
                    if (
                      Value === "comment" ||
                      Value === "edit" ||
                      Value === "review" ||
                      Value === "view"
                    )
                      SetMode(Value);
                  }}
                  value={Mode}
                >
                  <option value="view">{En.documentModeView}</option>
                  <option value="comment">{En.documentModeComment}</option>
                  <option value="review">{En.documentModeReview}</option>
                  <option value="edit">{En.documentModeEdit}</option>
                </Select>
              </label>
              {ErrorMessage === null ? null : (
                <div className="fb-error" role="alert">
                  {ErrorMessage}
                </div>
              )}
            </DialogContent>
            <DialogActions>
              <Button appearance="secondary" disabled={Busy} onClick={OnClose}>
                {En.close}
              </Button>
              <Button appearance="primary" disabled={Busy} type="submit">
                {Busy
                  ? En.working
                  : PreparedLaunch === null
                    ? En.documentPrepare
                    : En.documentLaunch}
              </Button>
            </DialogActions>
          </DialogBody>
        </form>
      </DialogSurface>
    </Dialog>
  );
}

/** Posts a Core-issued one-use grant without putting it in a URL or browser storage. */
export function SubmitDocumentLaunch(Handoff: DocumentSessionLaunchHandoff): void {
  if (!IsIsolatedDocumentLaunchAction(Handoff.action, window.location.hostname))
    throw new Error(En.offline);
  const Form = document.createElement("form");
  Form.action = Handoff.action;
  Form.method = "post";
  Form.target = "_self";
  Form.noValidate = true;
  const Grant = document.createElement("input");
  Grant.name = "launch_grant";
  Grant.type = "hidden";
  Grant.value = Handoff.grant;
  Form.append(Grant);
  document.body.append(Form);
  Form.submit();
  Form.remove();
}

/** Accept only the configured isolated HTTPS editor handoff route. */
export function IsIsolatedDocumentLaunchAction(Action: string, PublicHostname: string): boolean {
  try {
    const Url = new URL(Action);
    return (
      Url.protocol === "https:" &&
      Url.hostname !== PublicHostname &&
      !Url.hostname.endsWith(".") &&
      Url.pathname === "/onlyoffice/launch" &&
      Url.username === "" &&
      Url.password === "" &&
      Url.port === "" &&
      Url.search === "" &&
      Url.hash === ""
    );
  } catch {
    return false;
  }
}

interface OwnDocumentSessionsProps {
  Client: DocumentSessionClient;
  OnWorkspaceChanged?(): Promise<void> | void;
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns nested props and the optional lifecycle callback is receiver-free.
export function OwnDocumentSessions({
  Client,
  OnWorkspaceChanged,
}: OwnDocumentSessionsProps): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const [Page, SetPage] = useState<components["schemas"]["DocumentSessionPage"] | null>(null);
  const [Detail, SetDetail] = useState<DocumentSessionDetail | null>(null);
  const [Busy, SetBusy] = useState(false);
  const [ErrorMessage, SetErrorMessage] = useState<string | null>(null);
  const [Announcement, SetAnnouncement] = useState("");

  const HandleFailure = useCallback((Cause: unknown): void => {
    SetErrorMessage(Cause instanceof Error ? Cause.message : En.offline);
  }, []);

  const Refresh = useCallback(
    async (Signal?: Readonly<AbortSignal>): Promise<void> => {
      try {
        SetPage(await Client.listOwnSessions({ ...(Signal === undefined ? {} : { Signal }) }));
        SetErrorMessage(null);
      } catch (Cause) {
        if (!(Cause instanceof DOMException && Cause.name === "AbortError")) HandleFailure(Cause);
      }
    },
    [Client, HandleFailure],
  );

  useEffect(() => {
    const Controller = new AbortController();
    void Refresh(Controller.signal);
    return () => {
      Controller.abort();
    };
  }, [Refresh]);

  const Mutate = async (
    Operation: () => Promise<unknown>,
    Message: string,
    WorkspaceChanged = false,
  ): Promise<void> => {
    SetBusy(true);
    SetErrorMessage(null);
    try {
      await Operation();
      if (WorkspaceChanged) await OnWorkspaceChanged?.();
      await Refresh();
      SetAnnouncement(Message);
    } catch (Cause) {
      HandleFailure(Cause);
    } finally {
      SetBusy(false);
    }
  };

  const LoadMore = async (): Promise<void> => {
    const Cursor = Page?.next_cursor;
    if (Cursor === null || Cursor === undefined) return;
    SetBusy(true);
    SetErrorMessage(null);
    try {
      const NextPage = await Client.listOwnSessions({ Cursor });
      SetPage((Current) =>
        Current === null
          ? NextPage
          : {
              items: [...Current.items, ...NextPage.items],
              next_cursor: NextPage.next_cursor,
            },
      );
    } catch (Cause) {
      HandleFailure(Cause);
    } finally {
      SetBusy(false);
    }
  };

  if (Page === null && ErrorMessage === null)
    return (
      <section aria-busy="true" aria-label={En.documentSessions}>
        <Spinner label={En.documentSessions} />
      </section>
    );
  return (
    <section aria-labelledby="document-sessions-heading" className="fb-document-page">
      <header className="fb-page-heading">
        <div>
          <p className="fb-eyebrow">{En.documentExternalEditor}</p>
          <h1 id="document-sessions-heading">{En.documentSessions}</h1>
          <p className="fb-muted">{En.documentSessionsDescription}</p>
        </div>
      </header>
      {ErrorMessage === null ? null : (
        <div className="fb-error" role="alert">
          {ErrorMessage}
        </div>
      )}
      <div className="fb-card-list" role="list">
        {Page?.items.map((Session) => (
          <SessionCard
            Busy={Busy}
            Client={Client}
            key={Session.id}
            OnDetail={SetDetail}
            OnFailure={HandleFailure}
            OnMutate={Mutate}
            Session={Session}
          />
        ))}
        {Page?.items.length === 0 ? <p>{En.documentSessionsEmpty}</p> : null}
      </div>
      {Page?.next_cursor === null || Page === null ? null : (
        <Button appearance="secondary" disabled={Busy} onClick={() => void LoadMore()}>
          {En.documentLoadMore}
        </Button>
      )}
      {Detail === null ? null : (
        <SessionDetail
          DialogDetail={Detail}
          OnClose={() => {
            SetDetail(null);
          }}
        />
      )}
      <div aria-atomic="true" aria-live="polite" className="fb-sr-only">
        {Announcement}
      </div>
    </section>
  );
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns nested props and card callbacks are receiver-free parent functions.
function SessionCard({
  Busy,
  Client,
  OnDetail,
  OnFailure,
  OnMutate,
  Session,
}: {
  Busy: boolean;
  Client: DocumentSessionClient;
  OnDetail(Detail: DocumentSessionDetail): void;
  OnFailure(Cause: unknown): void;
  OnMutate(
    Operation: () => Promise<unknown>,
    Message: string,
    WorkspaceChanged?: boolean,
  ): Promise<void>;
  Session: components["schemas"]["DocumentSessionSummary"];
}): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const [ConfirmRevoke, SetConfirmRevoke] = useState(false);
  const LoadDetail = async (): Promise<void> => {
    try {
      OnDetail(await Client.getOwnSession(Session.id));
    } catch (Cause) {
      OnFailure(Cause);
    }
  };
  const IsConflict = Session.state === "conflicted";
  return (
    <>
      <article className="fb-activity-card fb-document-session" role="listitem">
        <FileBeltIcon Icon={IsConflict ? FileWarning : MonitorCog} />
        <div className="fb-grow">
          <strong>
            {ModeLabel(Session.mode)} · {StatusLabel(Session.state)}
          </strong>
          <span className="fb-muted">
            {En.documentParticipantCount(Session.participant_count)} ·{" "}
            <time dateTime={Session.last_activity_at}>{FormatDate(Session.last_activity_at)}</time>
          </span>
          {IsConflict ? <span className="fb-document-conflict">{En.documentConflict}</span> : null}
        </div>
        <Button appearance="secondary" disabled={Busy} onClick={() => void LoadDetail()}>
          {En.details}
        </Button>
        {IsConflict ? (
          <Button
            appearance="primary"
            disabled={Busy}
            onClick={() =>
              void OnMutate(
                async () =>
                  Client.createConflictCopy(
                    Session.id,
                    En.documentConflictCopyName(En.documentDefaultName),
                  ),
                En.documentConflictCopy,
                true,
              )
            }
          >
            {En.documentConflictCopy}
          </Button>
        ) : (
          <Button
            appearance="secondary"
            aria-haspopup="dialog"
            disabled={Busy || Session.state !== "active"}
            onClick={() => {
              SetConfirmRevoke(true);
            }}
          >
            {En.revoke}
          </Button>
        )}
      </article>
      <Dialog
        modalType="alert"
        onOpenChange={(Ignored, Data) => {
          if (!Data.open && !Busy) SetConfirmRevoke(false);
        }}
        open={ConfirmRevoke}
      >
        <DialogSurface>
          <DialogBody>
            <DialogTitle>{En.documentRevokeHeading}</DialogTitle>
            <DialogContent>{En.documentRevokeConfirmation}</DialogContent>
            <DialogActions>
              <Button
                appearance="secondary"
                disabled={Busy}
                onClick={() => {
                  SetConfirmRevoke(false);
                }}
              >
                {En.cancel}
              </Button>
              <Button
                appearance="primary"
                disabled={Busy}
                onClick={() => {
                  SetConfirmRevoke(false);
                  void OnMutate(
                    async () => Client.revokeOwnSession(Session.id),
                    En.documentSessionRevoked,
                  );
                }}
              >
                {En.revoke}
              </Button>
            </DialogActions>
          </DialogBody>
        </DialogSurface>
      </Dialog>
    </>
  );
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns the generated detail prop and the close callback is receiver-free.
function SessionDetail({
  DialogDetail,
  OnClose,
}: {
  DialogDetail: DocumentSessionDetail;
  OnClose(): void;
}): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const TitleId = useId();
  return (
    <Dialog
      modalType="modal"
      open
      onOpenChange={(Ignored, Data) => {
        if (!Data.open) OnClose();
      }}
    >
      <DialogSurface className="fb-document-dialog">
        <DialogBody>
          <DialogTitle id={TitleId}>{En.documentSessions}</DialogTitle>
          <DialogContent>
            <p className="fb-muted">{En.documentCollaborators}</p>
            <ul className="fb-document-participants" aria-labelledby={TitleId}>
              {DialogDetail.participants.map((Participant) => (
                <li key={Participant.principal_id}>
                  <UserRoundCheck aria-hidden="true" size={18} />
                  <BidiText>{Participant.display_name}</BidiText>
                  <StatusPill Kind={Participant.active ? "success" : "informative"}>
                    {Participant.active ? En.documentStatusActive : En.documentStatusClosed}
                  </StatusPill>
                </li>
              ))}
            </ul>
          </DialogContent>
          <DialogActions>
            <Button appearance="primary" onClick={OnClose}>
              {En.close}
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}

/** Shown only when a future capability projection confirms file-session authority; server authorization remains decisive. */
// oxlint-disable typescript/prefer-readonly-parameter-types -- React owns this nested props object and the component only observes it.
export function FileDocumentSessionManagement({
  CanManage,
  Client,
  DriveId,
  NodeId,
}: {
  CanManage: boolean;
  Client: DocumentSessionClient;
  DriveId: string;
  NodeId: string;
}): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types
  const [Page, SetPage] = useState<components["schemas"]["DocumentSessionPage"] | null>(null);
  const [ErrorMessage, SetErrorMessage] = useState<string | null>(null);
  if (!CanManage) return null;
  const Load = async (): Promise<void> => {
    try {
      SetPage(await Client.listNodeSessions(DriveId, NodeId));
      SetErrorMessage(null);
    } catch (Cause) {
      SetErrorMessage(Cause instanceof Error ? Cause.message : En.offline);
    }
  };
  return (
    <section className="fb-document-management" aria-label={En.documentSessions}>
      <Button appearance="secondary" onClick={() => void Load()}>
        {En.documentSessions}
      </Button>
      {ErrorMessage === null ? null : (
        <div className="fb-error" role="alert">
          {ErrorMessage}
        </div>
      )}
      {Page === null ? null : (
        <div className="fb-card-list" role="list">
          {Page.items.map((Session) => (
            <article className="fb-activity-card" key={Session.id} role="listitem">
              <div className="fb-grow">
                <strong>{ModeLabel(Session.mode)}</strong>
                <span className="fb-muted">
                  {En.documentParticipantCount(Session.participant_count)} ·{" "}
                  {StatusLabel(Session.state)}
                </span>
              </div>
              <Button appearance="secondary" onClick={() => void Client.forceClose(Session)}>
                {En.documentForceClose}
              </Button>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function ModeLabel(Mode: DocumentSessionMode): string {
  return {
    comment: En.documentModeComment,
    edit: En.documentModeEdit,
    review: En.documentModeReview,
    view: En.documentModeView,
  }[Mode];
}

function StatusLabel(State: components["schemas"]["DocumentSessionSummary"]["state"]): string {
  return {
    active: En.documentStatusActive,
    closed: En.documentStatusClosed,
    conflicted: En.documentStatusConflicted,
    expired: En.documentStatusExpired,
    revoked: En.documentStatusRevoked,
  }[State];
}

function FormatDate(Value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(Value),
  );
}
