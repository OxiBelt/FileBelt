// SPDX-License-Identifier: Apache-2.0

import { Badge, Button, Input, Tab as FluentTab, TabList } from '@fluentui/react-components'
import {
  CircleGauge,
  HardDrive,
  Network,
  Plus,
  ShieldCheck,
  Users as UsersIcon,
} from 'lucide-react'
import { useState } from 'react'
import type { ComponentProps, ReactNode } from 'react'

import { AdminEn as strings } from './strings.js'
import { NfsAdminSurface } from './nfs.js'
import type { NfsAdminClient } from './nfs.js'

export {
  ExportTransitions,
  FeatureTransitions,
  NfsAdminOverviewView,
  NfsAdminSurface,
  NfsReauthenticationRequiredError,
} from './nfs.js'
export type {
  NfsAdminClient,
  NfsAdminSnapshot,
  NfsConflictCopy,
  NfsConflictView,
  NfsExportRegistration,
  NfsExportState,
  NfsExportView,
  NfsFeatureState,
  NfsFeatureView,
  // oxlint-disable-next-line typescript/no-deprecated -- Retained as the public proposal-shape compatibility export.
  NfsMappingUpsert,
  NfsMappingView,
  NfsPosixGroupRegistration,
  NfsPosixGroupView,
} from './nfs.js'

export interface AdminUserView {
  Email: string
  Id: string
  Name: string
  Status: 'active' | 'suspended'
}

export interface AdminGroupView {
  Id: string
  ManagerCount: number
  MemberCount: number
  Name: string
}

export interface AdminDriveView {
  Id: string
  Name: string
  QuotaBytes: number
  UsedBytes: number
}

export interface AdminPanelProps {
  Drives: readonly AdminDriveView[]
  Groups: readonly AdminGroupView[]
  OnCreateGroup(Name: string): Promise<void>
  OnCreateSharedDrive(Name: string): Promise<void>
  OnToggleUserSuspension(UserId: string): Promise<void>
  NfsClient?: NfsAdminClient
  Users: readonly AdminUserView[]
}

type AdminTab = 'drives' | 'groups' | 'nfs' | 'users'

function FormatBytes(Value: number): string {
  return new Intl.NumberFormat(undefined, {
    maximumFractionDigits: 1,
    notation: 'compact',
    style: 'unit',
    unit: 'byte',
    unitDisplay: 'narrow',
  }).format(Value)
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns and may clone component props.
function Bidi({
  children: Children,
}: {
  // oxlint-disable-next-line filebelt/pascal-case -- React reserves `children` for nested JSX content.
  children: string
}): ReactNode {
  return <bdi dir='auto'>{Children}</bdi>
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns and may clone component props.
function CreationForm({
  Label,
  // oxlint-disable-next-line typescript/unbound-method -- The component callback is a receiver-free parent function.
  OnCreate,
}: {
  Label: string
  OnCreate(Value: string): Promise<void>
}): ReactNode {
  const [Name, SetName] = useState('')
  const [Busy, SetBusy] = useState(false)

  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React submit events must remain mutable for preventDefault.
  const Submit = async (Event: HtmlFormSubmitEvent): Promise<void> => {
    Event.preventDefault()
    const Trimmed = Name.trim()
    if (Trimmed.length === 0) return
    SetBusy(true)
    try {
      await OnCreate(Trimmed)
      SetName('')
    } finally {
      SetBusy(false)
    }
  }

  return (
    <form className='fb-admin-create' onSubmit={(Event) => void Submit(Event)}>
      <Input
        aria-label={Label}
        disabled={Busy}
        onChange={(Ignored, Data) => {
          SetName(Data.value)
        }}
        placeholder={Label}
        value={Name}
      />
      <Button
        appearance='primary'
        disabled={Busy || Name.trim().length === 0}
        icon={<Plus aria-hidden='true' size={20} strokeWidth={1.75} />}
        type='submit'
      >
        {strings.create}
      </Button>
    </form>
  )
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns and may clone component props.
export default function AdminPanel({
  Drives,
  Groups,
  // oxlint-disable-next-line typescript/unbound-method -- React callback props are invoked as functions and deliberately have no receiver.
  OnCreateGroup,
  // oxlint-disable-next-line typescript/unbound-method -- React callback props are invoked as functions and deliberately have no receiver.
  OnCreateSharedDrive,
  // oxlint-disable-next-line typescript/unbound-method -- React callback props are invoked as functions and deliberately have no receiver.
  OnToggleUserSuspension,
  NfsClient,
  Users,
}: AdminPanelProps): ReactNode {
  const [Tab, SetTab] = useState<AdminTab>('users')
  const [BusyUserId, SetBusyUserId] = useState<string | null>(null)

  const ToggleUser = async (UserId: string): Promise<void> => {
    SetBusyUserId(UserId)
    try {
      await OnToggleUserSuspension(UserId)
    } finally {
      SetBusyUserId(null)
    }
  }

  return (
    <section aria-labelledby='admin-heading' className='fb-admin-page'>
      <header className='fb-page-heading'>
        <div>
          <p className='fb-eyebrow'>
            <ShieldCheck aria-hidden='true' size={18} strokeWidth={1.75} /> {strings.heading}
          </p>
          <h1 id='admin-heading'>{strings.heading}</h1>
          <p className='fb-muted'>{strings.reauth}</p>
        </div>
      </header>

      <TabList
        aria-label={strings.heading}
        onTabSelect={(Ignored, Data) => {
          if (IsAdminTab(Data.value)) SetTab(Data.value)
        }}
        selectedValue={Tab}
      >
        <FluentTab
          icon={<UsersIcon aria-hidden='true' size={20} strokeWidth={1.75} />}
          value='users'
        >
          {strings.users}
        </FluentTab>
        <FluentTab
          icon={<CircleGauge aria-hidden='true' size={20} strokeWidth={1.75} />}
          value='groups'
        >
          {strings.groups}
        </FluentTab>
        <FluentTab
          icon={<HardDrive aria-hidden='true' size={20} strokeWidth={1.75} />}
          value='drives'
        >
          {strings.drives}
        </FluentTab>
        {NfsClient === undefined ? null : (
          <FluentTab icon={<Network aria-hidden='true' size={20} strokeWidth={1.75} />} value='nfs'>
            {strings.nfs}
          </FluentTab>
        )}
      </TabList>

      {Tab === 'users' ? (
        <div className='fb-admin-cards' role='list'>
          {Users.map((User) => (
            <article className='fb-admin-card' key={User.Id} role='listitem'>
              <div>
                <h2>
                  <Bidi>{User.Name}</Bidi>
                </h2>
                <p className='fb-muted'>
                  <Bidi>{User.Email}</Bidi>
                </p>
              </div>
              <Badge appearance='tint' color={User.Status === 'active' ? 'success' : 'danger'}>
                {User.Status === 'active' ? strings.active : strings.suspended}
              </Badge>
              <Button
                appearance={User.Status === 'active' ? 'secondary' : 'primary'}
                disabled={BusyUserId === User.Id}
                onClick={() => void ToggleUser(User.Id)}
              >
                {User.Status === 'active' ? strings.suspend : strings.resume}
              </Button>
            </article>
          ))}
        </div>
      ) : null}

      {Tab === 'groups' ? (
        <div>
          <CreationForm Label={strings.createGroup} OnCreate={OnCreateGroup} />
          <div className='fb-admin-cards' role='list'>
            {Groups.map((Group) => (
              <article className='fb-admin-card' key={Group.Id} role='listitem'>
                <div>
                  <h2>
                    <Bidi>{Group.Name}</Bidi>
                  </h2>
                </div>
                <dl className='fb-inline-stats'>
                  <div>
                    <dt>{strings.memberCount}</dt>
                    <dd>{Group.MemberCount}</dd>
                  </div>
                  <div>
                    <dt>{strings.managerCount}</dt>
                    <dd>{Group.ManagerCount}</dd>
                  </div>
                </dl>
              </article>
            ))}
          </div>
        </div>
      ) : null}

      {Tab === 'drives' ? (
        <div>
          <CreationForm Label={strings.driveName} OnCreate={OnCreateSharedDrive} />
          <div className='fb-admin-cards' role='list'>
            {Drives.map((Drive) => (
              <article className='fb-admin-card' key={Drive.Id} role='listitem'>
                <div>
                  <h2>
                    <Bidi>{Drive.Name}</Bidi>
                  </h2>
                  <p className='fb-muted'>
                    {strings.quota}: {FormatBytes(Drive.QuotaBytes)}
                  </p>
                </div>
                <div className='fb-quota'>
                  <span>
                    {strings.usage}: {FormatBytes(Drive.UsedBytes)}
                  </span>
                  <progress
                    aria-label={`${Drive.Name} ${strings.usage}`}
                    max={Drive.QuotaBytes}
                    value={Drive.UsedBytes}
                  />
                </div>
              </article>
            ))}
          </div>
        </div>
      ) : null}

      {Tab === 'nfs' && NfsClient !== undefined ? <NfsAdminSurface Client={NfsClient} /> : null}
    </section>
  )
}

type HtmlFormSubmitEvent = Parameters<NonNullable<ComponentProps<'form'>['onSubmit']>>[0]

function IsAdminTab(Value: unknown): Value is AdminTab {
  return Value === 'drives' || Value === 'groups' || Value === 'nfs' || Value === 'users'
}
