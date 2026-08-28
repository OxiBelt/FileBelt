// SPDX-License-Identifier: Apache-2.0

import {
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Input,
  Spinner,
} from '@fluentui/react-components'
import { Copy, HardDrive, KeyRound, Laptop, Network, ShieldCheck, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode, SyntheticEvent } from 'react'

import { BidiText, FileBeltIcon, StatusPill } from '@filebelt/design-system'

import {
  MountCredentialOutcomeUnknownError,
  MountReauthenticationRequiredError,
} from './mount-http-client.js'
import type {
  CreateMountCredential,
  CreatedMountCredential,
  MountCredentialOperation,
  MountOverview,
  MountProtocol,
  MountSettingsClient,
} from './mount-http-client.js'
import type {
  NfsMappingProposal,
  NfsPrincipalMapping,
  NfsTargetClient,
} from './nfs-target-http-client.js'

interface MountSettingsProps {
  Client: MountSettingsClient
  NfsClient?: NfsTargetClient | undefined
}

interface PolicyDraft {
  AllowedDriveIds: ReadonlySet<string>
  Enabled: boolean
}

const Protocols = ['smb', 'ftps'] as const

export function MountCredentialCreationBlocked(
  UnresolvedOperation: MountCredentialOperation | null,
): boolean {
  return UnresolvedOperation !== null
}

type MountCredentialDraft = Omit<CreateMountCredential, 'operation_generation' | 'operation_id'>

type MountCredentialCreationClient = Pick<
  MountSettingsClient,
  'CancelCredentialOperation' | 'CreateCredential' | 'PrepareCredentialOperation'
>

export class MountCredentialRecoveryRequiredError extends Error {
  readonly Operation: MountCredentialOperation

  constructor(Operation: MountCredentialOperation) {
    super(
      `Credential operation ${Operation.operation_id} generation ${Operation.operation_generation} could not be recovered. Retry recovery before creating another credential.`,
    )
    this.name = 'MountCredentialRecoveryRequiredError'
    this.Operation = Operation
  }
}

export async function CreateCredentialWithRecovery(
  Client: MountCredentialCreationClient,
  Draft: MountCredentialDraft,
): Promise<CreatedMountCredential> {
  const { Operation } = await Client.PrepareCredentialOperation()
  try {
    return await Client.CreateCredential({
      ...Draft,
      operation_generation: Operation.operation_generation,
      operation_id: Operation.operation_id,
    })
  } catch (Cause) {
    if (!(Cause instanceof MountCredentialOutcomeUnknownError)) throw Cause
    try {
      await Client.CancelCredentialOperation(Operation.operation_id, Operation.operation_generation)
    } catch {
      throw new MountCredentialRecoveryRequiredError(Operation)
    }
    throw new Error(
      'The creation response was interrupted. Any credential from that operation was revoked; create a new credential to receive a new password.',
    )
  }
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns the nested client props and this component only observes them.
export function MountSettings({ Client, NfsClient }: MountSettingsProps): ReactNode {
  const [Snapshot, SetSnapshot] = useState<MountOverview | null>(null)
  const [Drafts, SetDrafts] = useState<Record<MountProtocol, PolicyDraft> | null>(null)
  const [Busy, SetBusy] = useState(false)
  const [ErrorMessage, SetErrorMessage] = useState<string | null>(null)
  const [Announcement, SetAnnouncement] = useState('')
  const [Created, SetCreated] = useState<CreatedMountCredential | null>(null)
  const [ReauthenticationRequired, SetReauthenticationRequired] = useState(false)
  const [PendingCredentialId, SetPendingCredentialId] = useState<string | null>(null)

  const Refresh = useCallback(
    async (Signal?: Readonly<AbortSignal>): Promise<void> => {
      try {
        const Next = await Client.GetOverview(Signal)
        SetSnapshot(Next)
        SetDrafts(PolicyDrafts(Next))
        SetErrorMessage(null)
      } catch (Cause) {
        if (!(Cause instanceof DOMException && Cause.name === 'AbortError')) {
          SetErrorMessage(
            Cause instanceof Error ? Cause.message : 'Mount settings are unavailable.',
          )
        }
      }
    },
    [Client],
  )

  useEffect(() => {
    const Controller = new AbortController()
    void Refresh(Controller.signal)
    return () => {
      Controller.abort()
    }
  }, [Refresh])

  const Mutate = async (Operation: () => Promise<void>, Message: string): Promise<void> => {
    SetBusy(true)
    SetErrorMessage(null)
    SetReauthenticationRequired(false)
    try {
      await Operation()
      await Refresh()
      SetAnnouncement(Message)
    } catch (Cause) {
      if (Cause instanceof MountReauthenticationRequiredError) SetReauthenticationRequired(true)
      else
        SetErrorMessage(
          Cause instanceof Error ? Cause.message : 'The mount setting was not changed.',
        )
    } finally {
      SetBusy(false)
    }
  }

  if ((Snapshot === null || Drafts === null) && ErrorMessage !== null) {
    return (
      <section aria-labelledby='mounts-unavailable-heading' className='fb-mount-page'>
        <h1 id='mounts-unavailable-heading'>Mounted access</h1>
        <div className='fb-error' role='alert'>
          {ErrorMessage}
        </div>
        <Button appearance='primary' disabled={Busy} onClick={() => void Refresh()}>
          Try again
        </Button>
      </section>
    )
  }

  if (Snapshot === null || Drafts === null) {
    return (
      <section aria-busy='true' aria-label='Mount settings'>
        <Spinner label='Loading mount settings' />
      </section>
    )
  }
  const PendingCredential = Snapshot.credentials.find(({ id: Id }) => Id === PendingCredentialId)

  return (
    <section aria-labelledby='mounts-heading' className='fb-mount-page'>
      <header className='fb-page-heading'>
        <div>
          <p className='fb-eyebrow'>Network access</p>
          <h1 id='mounts-heading'>Mounted access</h1>
          <p className='fb-muted'>
            Create separately scoped, read-only SMB or explicit FTPS credentials for selected
            drives. FileBelt account passwords are never accepted.
          </p>
        </div>
      </header>

      {ErrorMessage === null ? null : (
        <div className='fb-error' role='alert'>
          {ErrorMessage}
        </div>
      )}
      {ReauthenticationRequired ? (
        <div className='fb-mount-reauth' role='alert'>
          <p>Credential changes require a recent OIDC sign-in.</p>
          <Button
            appearance='primary'
            as='a'
            href='/api/v1/auth/login?return_path=%2Fsettings%2Fmounts'
          >
            Sign in again
          </Button>
        </div>
      ) : null}

      {NfsClient === undefined ? null : (
        <NfsConsentSettings
          Client={NfsClient}
          OnReauthenticationRequired={() => {
            SetReauthenticationRequired(true)
          }}
        />
      )}

      <div className='fb-mount-grid'>
        {Protocols.map((Protocol) => (
          <PolicyCard
            Busy={Busy}
            Draft={Drafts[Protocol]}
            Drives={Snapshot.drives}
            key={Protocol}
            OnChange={(Draft) => {
              SetDrafts((Current) =>
                Current === null ? Current : { ...Current, [Protocol]: Draft },
              )
            }}
            OnSave={async () =>
              Mutate(
                async () =>
                  Client.PutPolicy(Protocol, {
                    allowed_drive_ids: [...Drafts[Protocol].AllowedDriveIds],
                    enabled: Drafts[Protocol].Enabled,
                    read_only: true,
                  }),
                `${Protocol.toUpperCase()} mount policy saved. Existing credentials were revoked.`,
              )
            }
            Protocol={Protocol}
          />
        ))}
      </div>

      <CredentialCreator
        Busy={Busy}
        Client={Client}
        Devices={Snapshot.devices.filter(({ revoked_at: RevokedAt }) => RevokedAt === null)}
        Policies={Snapshot.policies}
        OnCreated={(Value) => {
          SetCreated(Value)
          SetAnnouncement(
            `${Value.protocol.toUpperCase()} credential created. Its password is shown once.`,
          )
          void Refresh()
        }}
        OnError={(Cause) => {
          if (Cause instanceof MountReauthenticationRequiredError) SetReauthenticationRequired(true)
          else
            SetErrorMessage(
              Cause instanceof Error ? Cause.message : 'The mount credential was not created.',
            )
        }}
        SetBusy={SetBusy}
      />

      {Created === null ? null : (
        <OneTimeCredential
          Created={Created}
          OnClose={() => {
            SetCreated(null)
          }}
        />
      )}

      <section aria-labelledby='mount-credentials-heading' className='fb-mount-section'>
        <div className='fb-mount-section-heading'>
          <div>
            <h2 id='mount-credentials-heading'>Credentials</h2>
            <p className='fb-muted'>
              Passwords cannot be recovered. Revoke and replace a credential if it is lost.
            </p>
          </div>
        </div>
        <div className='fb-card-list' role='list'>
          {Snapshot.credentials.map((Credential) => (
            <article className='fb-activity-card' key={Credential.id} role='listitem'>
              <FileBeltIcon Icon={KeyRound} />
              <div className='fb-grow'>
                <strong>
                  <BidiText>{Credential.username}</BidiText>
                </strong>
                <span className='fb-muted'>
                  {Credential.protocol.toUpperCase()} ·{' '}
                  {Credential.read_only ? 'read only' : 'read and write'} · expires{' '}
                  <time dateTime={Credential.expires_at}>{FormatDate(Credential.expires_at)}</time>
                </span>
              </div>
              {Credential.revoked_at === null ? (
                <Button
                  appearance='secondary'
                  aria-haspopup='dialog'
                  disabled={Busy}
                  onClick={() => {
                    SetPendingCredentialId(Credential.id)
                  }}
                >
                  Revoke
                </Button>
              ) : (
                <StatusPill Kind='danger'>Revoked</StatusPill>
              )}
            </article>
          ))}
          {Snapshot.credentials.length === 0 ? (
            <p>No mount credentials have been created.</p>
          ) : null}
        </div>
      </section>

      <Dialog
        modalType='alert'
        onOpenChange={(Ignored, Data) => {
          if (!Data.open && !Busy) SetPendingCredentialId(null)
        }}
        open={PendingCredential !== undefined}
      >
        <DialogSurface>
          <DialogBody>
            <DialogTitle>Revoke mount credential?</DialogTitle>
            <DialogContent>
              {PendingCredential === undefined
                ? ''
                : `Revoke ${PendingCredential.username}? Its active mount sessions will stop and its password cannot be recovered.`}
            </DialogContent>
            <DialogActions>
              <Button
                appearance='secondary'
                disabled={Busy}
                onClick={() => {
                  SetPendingCredentialId(null)
                }}
              >
                Cancel
              </Button>
              <Button
                appearance='primary'
                disabled={Busy || PendingCredential === undefined}
                onClick={() => {
                  if (PendingCredential === undefined) return
                  const CredentialId = PendingCredential.id
                  SetPendingCredentialId(null)
                  void Mutate(
                    async () => Client.RevokeCredential(CredentialId),
                    'Mount credential revoked.',
                  )
                }}
              >
                Revoke
              </Button>
            </DialogActions>
          </DialogBody>
        </DialogSurface>
      </Dialog>

      <div className='fb-mount-grid'>
        <SummaryList
          Heading='Tailnet devices'
          Icon={Laptop}
          Items={Snapshot.devices.map((Device) => ({
            Detail: Device.tailnet_addresses.join(', '),
            Id: Device.id,
            Name: Device.display_name,
            State: Device.revoked_at === null ? 'Current' : 'Revoked',
          }))}
        />
        <SummaryList
          Heading='Recent mount sessions'
          Icon={Network}
          Items={Snapshot.sessions.map((Session) => ({
            Detail: FormatMountSessionDetail(Session),
            Id: Session.id,
            Name: Session.gateway_id,
            State: Session.state,
          }))}
        />
      </div>
      <div aria-atomic='true' aria-live='polite' className='fb-sr-only'>
        {Announcement}
      </div>
    </section>
  )
}

export function FormatMountSessionDetail(Session: MountOverview['sessions'][number]): string {
  return `${Session.protocol.toUpperCase()} · transport/relay peer ${Session.source_address} · ${FormatDate(Session.last_activity_at)}`
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns nested props and the lifecycle callback is receiver-free.
function NfsConsentSettings({
  Client,
  OnReauthenticationRequired,
}: {
  Client: NfsTargetClient
  OnReauthenticationRequired(): void
}): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const [Mappings, SetMappings] = useState<readonly NfsPrincipalMapping[]>([])
  const [Proposals, SetProposals] = useState<readonly NfsMappingProposal[]>([])
  const [Busy, SetBusy] = useState(false)
  const [Loading, SetLoading] = useState(true)
  const [ErrorMessage, SetErrorMessage] = useState<string | null>(null)
  const [Announcement, SetAnnouncement] = useState('')

  const Refresh = useCallback(
    async (Signal?: Readonly<AbortSignal>): Promise<void> => {
      try {
        const Overview = await Client.GetOverview(Signal)
        SetMappings(Overview.mappings)
        SetProposals(Overview.proposals.filter(({ state: State }) => State === 'pending'))
        SetErrorMessage(null)
      } catch (Cause) {
        if (!(Cause instanceof DOMException && Cause.name === 'AbortError')) {
          SetErrorMessage(Cause instanceof Error ? Cause.message : 'NFS approvals are unavailable.')
        }
      } finally {
        SetLoading(false)
      }
    },
    [Client],
  )

  useEffect(() => {
    const Controller = new AbortController()
    void Refresh(Controller.signal)
    const Poll = window.setInterval(() => void Refresh(Controller.signal), 30_000)
    return () => {
      window.clearInterval(Poll)
      Controller.abort()
    }
  }, [Refresh])

  const Mutate = async (Operation: () => Promise<void>, Message: string): Promise<void> => {
    SetBusy(true)
    SetErrorMessage(null)
    try {
      await Operation()
      await Refresh()
      SetAnnouncement(Message)
    } catch (Cause) {
      if (Cause instanceof MountReauthenticationRequiredError) OnReauthenticationRequired()
      else
        SetErrorMessage(
          Cause instanceof Error ? Cause.message : 'The NFS consent change was not applied.',
        )
    } finally {
      SetBusy(false)
    }
  }

  return (
    <section aria-busy={Loading} aria-labelledby='nfs-consent-heading' className='fb-mount-section'>
      <div className='fb-mount-section-heading'>
        <FileBeltIcon Icon={Network} />
        <div>
          <h2 id='nfs-consent-heading'>NFS identity approvals</h2>
          <p className='fb-muted'>
            Review exact server-held mapping fields. Approval lasts until a material mapping change
            or revocation; FileBelt access still requires the selected drive permissions.
          </p>
        </div>
      </div>
      {Loading ? <Spinner label='Loading NFS approvals' /> : null}
      {ErrorMessage === null ? null : (
        <div className='fb-error' role='alert'>
          {ErrorMessage}
        </div>
      )}
      {Loading ? null : (
        <>
          <section aria-labelledby='nfs-pending-consent-heading'>
            <h3 id='nfs-pending-consent-heading'>Pending approvals</h3>
            <div className='fb-card-list' role='list'>
              {Proposals.map((Proposal) => (
                <NfsProposalConsentCard
                  Busy={Busy}
                  key={Proposal.id}
                  OnApprove={async () =>
                    Mutate(
                      async () => Client.ApproveProposal(Proposal.id, Proposal.generation),
                      'NFS identity mapping approved.',
                    )
                  }
                  OnDecline={async () =>
                    Mutate(
                      async () => Client.DeclineProposal(Proposal.id, Proposal.generation),
                      'NFS identity mapping declined.',
                    )
                  }
                  Proposal={Proposal}
                />
              ))}
              {Proposals.length === 0 ? <p>No NFS mapping proposals await your approval.</p> : null}
            </div>
          </section>
          <section aria-labelledby='nfs-active-aliases-heading'>
            <h3 id='nfs-active-aliases-heading'>Approved NFS identities</h3>
            <div className='fb-card-list' role='list'>
              {Mappings.map((Mapping) => (
                <NfsActiveMappingCard
                  Busy={Busy}
                  key={Mapping.credential_id}
                  Mapping={Mapping}
                  OnRevoke={async () =>
                    Mutate(
                      async () => Client.RevokeMapping(Mapping.credential_id, Mapping.generation),
                      'NFS identity mapping revoked.',
                    )
                  }
                />
              ))}
              {Mappings.length === 0 ? <p>You have no approved NFS identities.</p> : null}
            </div>
          </section>
        </>
      )}
      <div aria-atomic='true' aria-live='polite' className='fb-sr-only'>
        {Announcement}
      </div>
    </section>
  )
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns the generated proposal prop and action callbacks are receiver-free.
export function NfsProposalConsentCard({
  Busy,
  OnApprove,
  OnDecline,
  Proposal,
}: {
  Busy: boolean
  OnApprove(): Promise<void>
  OnDecline(): Promise<void>
  Proposal: NfsMappingProposal
}): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const [Confirmed, SetConfirmed] = useState(false)
  const HelpId = `nfs-proposal-${Proposal.id}-help`
  return (
    <article className='fb-activity-card' role='listitem'>
      <FileBeltIcon Icon={ShieldCheck} />
      <div className='fb-grow'>
        <strong>
          <BidiText>{Proposal.kerberos_principal}</BidiText>
        </strong>
        <dl className='fb-nfs-generation-grid'>
          <div>
            <dt>FileBelt principal</dt>
            <dd>
              <BidiText>{Proposal.principal_id}</BidiText>
            </dd>
          </div>
          <div>
            <dt>Proposed by</dt>
            <dd>
              <BidiText>{Proposal.proposer_principal_id}</BidiText>
            </dd>
          </div>
          <div>
            <dt>Proposal ID</dt>
            <dd>
              <BidiText>{Proposal.id}</BidiText>
            </dd>
          </div>
          <div>
            <dt>Proposal generation</dt>
            <dd>{Proposal.generation}</dd>
          </div>
          <div>
            <dt>State</dt>
            <dd>{Proposal.state}</dd>
          </div>
          <div>
            <dt>Projected UID</dt>
            <dd>{Proposal.projected_uid}</dd>
          </div>
          <div>
            <dt>Projected GID</dt>
            <dd>{Proposal.projected_gid}</dd>
          </div>
          <div>
            <dt>POSIX user</dt>
            <dd>
              <BidiText>{Proposal.posix_name}</BidiText>
            </dd>
          </div>
          <div>
            <dt>Primary POSIX group</dt>
            <dd>
              <BidiText>{`${Proposal.posix_group_name} (${Proposal.posix_group_id})`}</BidiText>
            </dd>
          </div>
          <div>
            <dt>Allowed drives</dt>
            <dd>
              {Proposal.allowed_drives.map((Drive) => (
                <BidiText key={Drive.id}>{`${Drive.display_name} (${Drive.id}) `}</BidiText>
              ))}
            </dd>
          </div>
          <div>
            <dt>Created</dt>
            <dd>
              <time dateTime={Proposal.created_at}>{FormatDate(Proposal.created_at)}</time>
            </dd>
          </div>
          <div>
            <dt>Expires</dt>
            <dd>
              <time dateTime={Proposal.expires_at}>{FormatDate(Proposal.expires_at)}</time>
            </dd>
          </div>
        </dl>
        <p className='fb-muted' id={HelpId}>
          Approve only if this exact Kerberos identity, numeric POSIX projection, and drive ceiling
          belong to you. Approval does not bypass Virtual ACL checks.
        </p>
        <Checkbox
          aria-describedby={HelpId}
          checked={Confirmed}
          disabled={Busy}
          label='I reviewed and approve these exact NFS identity fields'
          onChange={(Ignored, Data) => {
            SetConfirmed(Data.checked === true)
          }}
        />
        <div className='fb-nfs-actions'>
          <Button
            appearance='primary'
            aria-describedby={HelpId}
            disabled={Busy || !Confirmed}
            onClick={() => {
              SetConfirmed(false)
              void OnApprove()
            }}
          >
            Approve
          </Button>
          <Button
            appearance='secondary'
            aria-describedby={HelpId}
            disabled={Busy}
            onClick={() => void OnDecline()}
          >
            Decline
          </Button>
        </div>
      </div>
    </article>
  )
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns the generated mapping prop and the action callback is receiver-free.
export function NfsActiveMappingCard({
  Busy,
  Mapping,
  OnRevoke,
}: {
  Busy: boolean
  Mapping: NfsPrincipalMapping
  OnRevoke(): Promise<void>
}): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const [Confirmed, SetConfirmed] = useState(false)
  const HelpId = `nfs-target-revoke-${Mapping.credential_id}-help`
  return (
    <article className='fb-activity-card' role='listitem'>
      <FileBeltIcon Icon={Network} />
      <div className='fb-grow'>
        <strong>
          <BidiText>{Mapping.kerberos_principal}</BidiText>
        </strong>
        <span className='fb-muted'>
          UID {Mapping.projected_uid} · GID {Mapping.projected_gid} · generation{' '}
          {Mapping.generation}
        </span>
        <span className='fb-muted'>
          Allowed drive IDs:{' '}
          {Mapping.allowed_drive_ids?.map((DriveId) => (
            <BidiText key={DriveId}>{`${DriveId} `}</BidiText>
          )) ?? 'Unavailable'}
        </span>
        <p className='fb-muted' id={HelpId}>
          Revocation immediately closes sessions for this alias. Other separately approved aliases
          keep their own exact drive ceilings.
        </p>
        <Checkbox
          aria-describedby={HelpId}
          checked={Confirmed}
          disabled={Busy}
          label='I confirm this NFS identity should be revoked'
          onChange={(Ignored, Data) => {
            SetConfirmed(Data.checked === true)
          }}
        />
        <Button
          appearance='secondary'
          aria-describedby={HelpId}
          disabled={Busy || !Confirmed}
          onClick={() => {
            SetConfirmed(false)
            void OnRevoke()
          }}
        >
          Revoke
        </Button>
      </div>
    </article>
  )
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns nested policy props and callbacks are receiver-free parent functions.
function PolicyCard({
  Busy,
  Draft,
  Drives,
  OnChange,
  OnSave,
  Protocol,
}: {
  Busy: boolean
  Draft: PolicyDraft
  Drives: MountOverview['drives']
  OnChange(Draft: PolicyDraft): void
  OnSave(): Promise<void>
  Protocol: MountProtocol
}): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const HeadingId = `mount-policy-${Protocol}`
  const Label = Protocol === 'smb' ? 'SMB 3.1.1' : 'Explicit FTPS'
  const ToggleDrive = (DriveId: string, Checked: boolean): void => {
    const Next = new Set(Draft.AllowedDriveIds)
    if (Checked) Next.add(DriveId)
    else Next.delete(DriveId)
    OnChange({ ...Draft, AllowedDriveIds: Next })
  }
  return (
    <form
      aria-labelledby={HeadingId}
      className='fb-mount-section'
      onSubmit={(Event) => {
        Event.preventDefault()
        void OnSave()
      }}
    >
      <div className='fb-mount-section-heading'>
        <FileBeltIcon Icon={Protocol === 'smb' ? HardDrive : ShieldCheck} />
        <div>
          <h2 id={HeadingId}>{Label}</h2>
          <p className='fb-muted'>
            {Protocol === 'smb'
              ? 'Signing and encryption required.'
              : 'TLS 1.3, PROT P, and passive mode required.'}
          </p>
        </div>
      </div>
      <Checkbox
        checked={Draft.Enabled}
        label='Enable this protocol'
        onChange={(Ignored, Data) => {
          OnChange({ ...Draft, Enabled: Data.checked === true })
        }}
      />
      <Checkbox checked disabled label='This release supports read-only access only' />
      <fieldset className='fb-mount-drives'>
        <legend>Available drives</legend>
        {Drives.map((Drive) => (
          <Checkbox
            checked={Draft.AllowedDriveIds.has(Drive.id)}
            key={Drive.id}
            label={Drive.display_name}
            onChange={(Ignored, Data) => {
              ToggleDrive(Drive.id, Data.checked === true)
            }}
          />
        ))}
      </fieldset>
      <Button
        appearance='primary'
        disabled={Busy || (Draft.Enabled && Draft.AllowedDriveIds.size === 0)}
        type='submit'
      >
        Save policy and revoke old credentials
      </Button>
    </form>
  )
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns generated client props and callbacks are receiver-free parent functions.
function CredentialCreator({
  Busy,
  Client,
  Devices,
  Policies,
  OnCreated,
  OnError,
  SetBusy,
}: {
  Busy: boolean
  Client: MountSettingsClient
  Devices: MountOverview['devices']
  Policies: MountOverview['policies']
  OnCreated(Value: CreatedMountCredential): void
  OnError(Cause: unknown): void
  SetBusy(Value: boolean): void
}): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const [Protocol, SetProtocol] = useState<MountProtocol>('smb')
  const [DeviceId, SetDeviceId] = useState('')
  const [UnresolvedOperation, SetUnresolvedOperation] = useState<MountCredentialOperation | null>(
    null,
  )
  const Policy = useMemo(
    () => Policies.find(({ protocol: Value }) => Value === Protocol),
    [Policies, Protocol],
  )
  const Allowed = useMemo(() => Policy?.allowed_drive_ids ?? [], [Policy])
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns and supplies the synthetic submit event contract.
  const Submit = async (Event: Readonly<SyntheticEvent<HTMLFormElement>>): Promise<void> => {
    Event.preventDefault()
    if (MountCredentialCreationBlocked(UnresolvedOperation)) return
    SetBusy(true)
    try {
      const ExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
      OnCreated(
        await CreateCredentialWithRecovery(Client, {
          allowed_drive_ids: Allowed,
          bound_device_id: DeviceId.length === 0 ? null : DeviceId,
          expires_at: ExpiresAt,
          protocol: Protocol,
          read_only: true,
        }),
      )
    } catch (Cause) {
      if (Cause instanceof MountCredentialRecoveryRequiredError)
        SetUnresolvedOperation(Cause.Operation)
      else SetUnresolvedOperation(null)
      OnError(Cause)
    } finally {
      SetBusy(false)
    }
  }
  return (
    <section aria-labelledby='create-mount-credential-heading' className='fb-mount-section'>
      <div className='fb-mount-section-heading'>
        <FileBeltIcon Icon={KeyRound} />
        <div>
          <h2 id='create-mount-credential-heading'>Create credential</h2>
          <p className='fb-muted'>
            A new random password expires in seven days and is displayed once.
          </p>
        </div>
      </div>
      <form className='fb-mount-create-form' onSubmit={(Event) => void Submit(Event)}>
        {UnresolvedOperation === null ? null : (
          <div className='fb-error' role='alert'>
            <span>
              Creation operation {UnresolvedOperation.operation_id} generation{' '}
              {UnresolvedOperation.operation_generation} must be recovered before another credential
              can be created.
            </span>
            <Button
              appearance='secondary'
              disabled={Busy}
              onClick={() => {
                SetBusy(true)
                void Client.CancelCredentialOperation(
                  UnresolvedOperation.operation_id,
                  UnresolvedOperation.operation_generation,
                ).then(
                  () => {
                    SetUnresolvedOperation(null)
                    OnError(
                      new Error(
                        'The unresolved credential operation was recovered. You can now create a new one-time credential.',
                      ),
                    )
                    SetBusy(false)
                  },
                  (Cause: unknown) => {
                    OnError(Cause)
                    SetBusy(false)
                  },
                )
              }}
              type='button'
            >
              Retry revocation
            </Button>
          </div>
        )}
        <label>
          Protocol
          <select
            onChange={(Event) => {
              const Value = Event.currentTarget.value
              if (Value === 'ftps' || Value === 'smb') SetProtocol(Value)
            }}
            value={Protocol}
          >
            <option value='smb'>SMB 3.1.1</option>
            <option value='ftps'>Explicit FTPS</option>
          </select>
        </label>
        <label>
          Device binding
          <select
            onChange={(Event) => {
              SetDeviceId(Event.currentTarget.value)
            }}
            value={DeviceId}
          >
            <option value=''>Any current tailnet device</option>
            {Devices.map((Device) => (
              <option key={Device.id} value={Device.id}>
                {Device.display_name}
              </option>
            ))}
          </select>
        </label>
        <Checkbox checked disabled label='Read only' />
        <p className='fb-muted'>
          The credential can access {Allowed.length} selected{' '}
          {Allowed.length === 1 ? 'drive' : 'drives'}.
        </p>
        <Button
          appearance='primary'
          disabled={
            Busy ||
            MountCredentialCreationBlocked(UnresolvedOperation) ||
            Policy?.enabled !== true ||
            Allowed.length === 0
          }
          type='submit'
        >
          Create one-time credential
        </Button>
      </form>
    </section>
  )
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns the generated credential prop and close callback is receiver-free.
function OneTimeCredential({
  Created,
  OnClose,
}: {
  Created: CreatedMountCredential
  OnClose(): void
}): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const CopyValue = async (Value: string, Label: string, InputId: string): Promise<void> => {
    const Status = document.querySelector<HTMLElement>('#mount-copy-status')
    const ClipboardApi = navigator.clipboard as Clipboard | undefined
    try {
      if (ClipboardApi === undefined) throw new Error('Clipboard access is unavailable.')
      await ClipboardApi.writeText(Value)
      if (Status !== null) Status.textContent = `${Label} copied.`
    } catch {
      const InputElement = document.querySelector<HTMLInputElement>(
        `#${InputId} input, #${InputId}`,
      )
      InputElement?.focus()
      InputElement?.select()
      if (Status !== null)
        Status.textContent = `${Label} could not be copied automatically. The value is selected for manual copying.`
    }
  }
  return (
    <section aria-labelledby='one-time-credential-heading' className='fb-mount-secret' role='alert'>
      <div className='fb-mount-section-heading'>
        <div>
          <h2 id='one-time-credential-heading'>Save this credential now</h2>
          <p>
            The password is not stored in retrievable form and will disappear when this panel
            closes.
          </p>
        </div>
        <Button
          appearance='subtle'
          aria-label='Close one-time credential'
          icon={<X aria-hidden='true' />}
          onClick={OnClose}
        />
      </div>
      <label>
        Username
        <div className='fb-mount-copy'>
          <Input id='mount-credential-username' readOnly value={Created.username} />
          <Button
            aria-label='Copy mount username'
            icon={<Copy aria-hidden='true' />}
            onClick={() =>
              void CopyValue(Created.username, 'Username', 'mount-credential-username')
            }
          />
        </div>
      </label>
      <label>
        Password
        <div className='fb-mount-copy'>
          <Input id='mount-credential-password' readOnly type='text' value={Created.password} />
          <Button
            aria-label='Copy mount password'
            icon={<Copy aria-hidden='true' />}
            onClick={() =>
              void CopyValue(Created.password, 'Password', 'mount-credential-password')
            }
          />
        </div>
      </label>
      <p id='mount-copy-status' role='status' />
    </section>
  )
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns this nested presentational props object and the component only observes it.
function SummaryList({
  Heading,
  Icon,
  Items,
}: {
  Heading: string
  Icon: typeof Laptop
  Items: readonly { Detail: string; Id: string; Name: string; State: string }[]
}): ReactNode {
  return (
    <section aria-label={Heading} className='fb-mount-section'>
      <h2>{Heading}</h2>
      <div className='fb-card-list' role='list'>
        {Items.map((Item) => (
          <article className='fb-activity-card' key={Item.Id} role='listitem'>
            <FileBeltIcon Icon={Icon} />
            <div className='fb-grow'>
              <strong>
                <BidiText>{Item.Name}</BidiText>
              </strong>
              <span className='fb-muted'>
                <BidiText>{Item.Detail}</BidiText>
              </span>
            </div>
            <StatusPill
              Kind={Item.State === 'active' || Item.State === 'Current' ? 'success' : 'subtle'}
            >
              {Item.State}
            </StatusPill>
          </article>
        ))}
        {Items.length === 0 ? <p>No records are available.</p> : null}
      </div>
    </section>
  )
}

function PolicyDrafts(Snapshot: MountOverview): Record<MountProtocol, PolicyDraft> {
  const Draft = (Protocol: MountProtocol): PolicyDraft => {
    const Policy = Snapshot.policies.find(({ protocol: Value }) => Value === Protocol)
    return {
      AllowedDriveIds: new Set(Policy?.allowed_drive_ids ?? []),
      Enabled: Policy?.enabled ?? false,
    }
  }
  return { ftps: Draft('ftps'), smb: Draft('smb') }
}

function FormatDate(Value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(Value),
  )
}
