// SPDX-License-Identifier: Apache-2.0

import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Spinner,
} from '@fluentui/react-components'
import { Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import { BidiText, FileBeltIcon } from '@filebelt/design-system'

import { AclConflictError } from './client.js'
import type {
  AclAction,
  AclCollection,
  AclEntry,
  AclEntryMutation,
  AclInheritance,
  AclPrincipalKind,
  AclPrincipalSelector,
  FileBeltClient,
} from './client.js'
import type { FileEntry } from './model.js'
import { En } from './strings.js'

interface AclEditorProps {
  Client: FileBeltClient
  Entry: Readonly<FileEntry>
  OnClose: () => void
  OnSaved: () => void
}

interface PrincipalGroup {
  Entries: readonly Readonly<AclEntry>[]
  Key: string
  Label: string
  Kind: AclPrincipalKind
  SelectorValue: string
}

export const AclScopeOptions: readonly AclInheritance[] = [
  'self',
  'children',
  'descendants',
  'self_and_descendants',
]

const ViewerActions: readonly AclAction[] = [
  'READ_METADATA',
  'LIST_CHILDREN',
  'READ_CONTENT',
  'USE_EXTERNAL_EDITOR',
]
const ContributorActions: readonly AclAction[] = [
  ...ViewerActions,
  'CREATE_CHILD',
  'WRITE_CONTENT',
  'CREATE_VERSION',
  'RENAME',
  'MOVE',
  'DELETE',
  'RESTORE',
  'SET_ATTRIBUTES',
  'COMMENT',
  'REVIEW',
]
const ManagerActions: readonly AclAction[] = [...ContributorActions, 'SHARE', 'MANAGE_ACL']

export const AclPresets = {
  Contributor: ContributorActions,
  Manager: ManagerActions,
  Viewer: ViewerActions,
} as const

export function PreserveAclDraftAfterConflict(
  Draft: readonly Readonly<AclEntryMutation>[],
  Collection: {
    readonly Entries: readonly Readonly<AclEntry>[]
    readonly SupportedActions: readonly AclAction[]
  },
): { Collection: AclCollection; Draft: readonly Readonly<AclEntryMutation>[] } {
  return { Collection, Draft }
}

export function GroupAclEntries(Entries: readonly Readonly<AclEntry>[]): readonly PrincipalGroup[] {
  const Groups = new Map<string, Readonly<AclEntry>[]>()
  for (const Entry of Entries) {
    const Values = Groups.get(Entry.PrincipalId) ?? []
    Values.push(Entry)
    Groups.set(Entry.PrincipalId, Values)
  }
  return [...Groups.entries()].map(([Key, Values]) => {
    const First = Values[0]
    if (First === undefined) throw new Error('An ACL principal group cannot be empty.')
    const SelectorValue =
      First.PrincipalKind === 'group' ? (First.GroupId ?? '') : (First.VerifiedEmail ?? '')
    return {
      Entries: Values,
      Key,
      Kind: First.PrincipalKind,
      Label: First.DisplayName || SelectorValue || Key,
      SelectorValue,
    }
  })
}

export function AclEditor({
  Client,
  Entry,
  OnClose,
  OnSaved,
}: Readonly<AclEditorProps>): ReactNode {
  const [Collection, SetCollection] = useState<AclCollection | null>(null)
  const [Etag, SetEtag] = useState<string | null>(null)
  const [ErrorMessage, SetErrorMessage] = useState<string | null>(null)
  const [Notice, SetNotice] = useState<string | null>(null)
  const [Loading, SetLoading] = useState(true)
  const [Saving, SetSaving] = useState(false)
  const [PrincipalKind, SetPrincipalKind] = useState<AclPrincipalKind>('user')
  const [Subject, SetSubject] = useState('')
  const [Draft, SetDraft] = useState<readonly AclEntryMutation[]>([])
  const [NewAction, SetNewAction] = useState<AclAction | ''>('')
  const [PresetScope, SetPresetScope] = useState<AclInheritance>('self')

  const Load = async (Signal?: Readonly<AbortSignal>): Promise<void> => {
    SetLoading(true)
    SetErrorMessage(null)
    try {
      const Current = await Client.GetAcl(Entry.Id, Signal)
      SetCollection(Current.Value)
      SetEtag(Current.Etag)
    } catch (Cause) {
      if (!(Cause instanceof DOMException && Cause.name === 'AbortError'))
        SetErrorMessage(Cause instanceof Error ? Cause.message : En.aclLoadFailed)
    } finally {
      if (Signal?.aborted !== true) SetLoading(false)
    }
  }

  useEffect(() => {
    const Controller = new AbortController()
    void Load(Controller.signal)
    return () => {
      Controller.abort()
    }
  }, [Client, Entry.Id])

  const Groups = useMemo(() => GroupAclEntries(Collection?.Entries ?? []), [Collection])
  const MissingActions =
    Collection?.SupportedActions.filter(
      (Action) => !Draft.some(({ Action: Existing }) => Existing === Action),
    ) ?? []
  const Selector = PrincipalSelector(PrincipalKind, Subject)
  const CanSave = Selector !== null && Etag !== null && Collection !== null && !Saving && !Loading

  const EditGroup = (Group: Readonly<PrincipalGroup>): void => {
    SetPrincipalKind(Group.Kind)
    SetSubject(Group.SelectorValue)
    SetDraft(
      Group.Entries.filter(({ ReadOnly, Source }) => Source === 'core' && !ReadOnly).map(
        ({ Action, Effect, Inheritance }) => ({ Action, Effect, Inheritance }),
      ),
    )
    SetNotice(En.aclEditingSubject(Group.Label))
    SetErrorMessage(null)
  }

  const ApplyPreset = (Actions: readonly AclAction[]): void => {
    SetDraft(Actions.map((Action) => ({ Action, Effect: 'allow', Inheritance: PresetScope })))
    SetNotice(En.aclPresetApplied)
  }

  const Save = async (): Promise<void> => {
    if (Selector === null || Etag === null || Collection === null || Saving || Loading) return
    SetSaving(true)
    SetErrorMessage(null)
    SetNotice(null)
    try {
      const Updated = await Client.ReplaceAcl(Entry.Id, Etag, Selector, Draft)
      SetCollection(Updated.Value)
      SetEtag(Updated.Etag)
      SetNotice(En.aclSaved)
      OnSaved()
    } catch (Cause) {
      if (Cause instanceof AclConflictError) {
        SetEtag(null)
        try {
          const Current = await Client.GetAcl(Entry.Id)
          const Refreshed = PreserveAclDraftAfterConflict(Draft, Current.Value)
          SetCollection(Refreshed.Collection)
          SetDraft(Refreshed.Draft)
          SetEtag(Current.Etag)
          SetNotice(En.aclConflictDraftPreserved)
        } catch (RefreshCause) {
          SetErrorMessage(
            RefreshCause instanceof Error ? RefreshCause.message : En.aclConflictRefreshFailed,
          )
        }
      } else SetErrorMessage(Cause instanceof Error ? Cause.message : En.aclSaveFailed)
    } finally {
      SetSaving(false)
    }
  }

  return (
    <Dialog
      modalType='modal'
      onOpenChange={(IgnoredEvent, Data) => {
        void IgnoredEvent
        if (!Data.open && !Saving) OnClose()
      }}
      open
    >
      <DialogSurface aria-describedby='acl-editor-description' className='fb-acl-dialog'>
        <DialogBody>
          <DialogTitle>
            <span className='fb-acl-title'>
              <FileBeltIcon Icon={ShieldCheck} /> {En.manageAccess}
            </span>
          </DialogTitle>
          <DialogContent className='fb-acl-content'>
            <p id='acl-editor-description'>
              {En.aclDescription}{' '}
              <strong>
                <BidiText>{Entry.Name}</BidiText>
              </strong>
            </p>
            {Loading ? <Spinner label={En.aclLoading} /> : null}
            {ErrorMessage === null ? null : (
              <div className='fb-error' role='alert'>
                <span>{ErrorMessage}</span>
                <Button appearance='transparent' onClick={() => void Load()}>
                  {En.retry}
                </Button>
              </div>
            )}
            {Notice === null ? null : (
              <p className='fb-acl-notice' role='status'>
                {Notice}
              </p>
            )}
            {Collection === null ? null : (
              <>
                <section aria-labelledby='acl-current-heading'>
                  <h2 id='acl-current-heading'>{En.aclCurrentRules}</h2>
                  {Groups.length === 0 ? <p className='fb-muted'>{En.aclNoDirectRules}</p> : null}
                  <div className='fb-acl-principals'>
                    {Groups.map((Group) => {
                      const Mutable = Group.Entries.some(
                        ({ ReadOnly, Source }) => Source === 'core' && !ReadOnly,
                      )
                      return (
                        <section className='fb-acl-principal' key={Group.Key}>
                          <header>
                            <div>
                              <h3>
                                <BidiText>{Group.Label}</BidiText>
                              </h3>
                              <p className='fb-muted'>
                                {Group.Kind === 'group' ? En.aclGroup : En.aclUser} ·{' '}
                                <BidiText>{Group.SelectorValue}</BidiText>
                              </p>
                            </div>
                            {Mutable ? (
                              <Button
                                appearance='secondary'
                                onClick={() => {
                                  EditGroup(Group)
                                }}
                              >
                                {En.edit}
                              </Button>
                            ) : null}
                          </header>
                          <div className='fb-acl-table-scroll'>
                            <table className='fb-acl-table'>
                              <thead>
                                <tr>
                                  <th>{En.aclAction}</th>
                                  <th>{En.aclEffect}</th>
                                  <th>{En.aclScope}</th>
                                  <th>{En.aclProvenance}</th>
                                </tr>
                              </thead>
                              <tbody>
                                {Group.Entries.map((Rule, Index) => (
                                  <tr
                                    key={`${Rule.Source}-${Rule.Action}-${Rule.Inheritance}-${Index}`}
                                  >
                                    <td>{ActionLabel(Rule.Action)}</td>
                                    <td>{EffectLabel(Rule.Effect)}</td>
                                    <td>{ScopeLabel(Rule.Inheritance)}</td>
                                    <td>
                                      {SourceLabel(Rule.Source)} ·{' '}
                                      {Rule.ReadOnly ? En.aclReadOnly : En.aclEditable}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </section>
                      )
                    })}
                  </div>
                </section>

                <section aria-labelledby='acl-editor-heading' className='fb-acl-edit'>
                  <h2 id='acl-editor-heading'>{En.aclEditRules}</h2>
                  <p className='fb-muted'>{En.aclReplacementWarning}</p>
                  <fieldset disabled={Saving}>
                    <legend>{En.aclExactSubject}</legend>
                    <div className='fb-acl-subject'>
                      <label>
                        {En.aclSubjectKind}
                        <select
                          value={PrincipalKind}
                          onChange={(Event) => {
                            const Kind = Event.currentTarget.value
                            if (Kind !== 'user' && Kind !== 'group') return
                            SetPrincipalKind(Kind)
                            SetSubject('')
                            SetDraft([])
                          }}
                        >
                          <option value='user'>{En.aclUser}</option>
                          <option value='group'>{En.aclGroup}</option>
                        </select>
                      </label>
                      <label>
                        {PrincipalKind === 'user' ? En.aclVerifiedEmail : En.aclGroupUuid}
                        <input
                          autoComplete={PrincipalKind === 'user' ? 'email' : 'off'}
                          inputMode={PrincipalKind === 'user' ? 'email' : 'text'}
                          onChange={(Event) => {
                            SetSubject(Event.currentTarget.value)
                          }}
                          placeholder={
                            PrincipalKind === 'user'
                              ? 'person@example.com'
                              : '00000000-0000-4000-8000-000000000000'
                          }
                          spellCheck={false}
                          type={PrincipalKind === 'user' ? 'email' : 'text'}
                          value={Subject}
                        />
                      </label>
                    </div>
                  </fieldset>

                  <fieldset className='fb-acl-presets' disabled={Saving}>
                    <legend>{En.aclReviewedPresets}</legend>
                    <label>
                      {En.aclPresetScope}
                      <select
                        value={PresetScope}
                        onChange={(Event) => {
                          const Scope = Event.currentTarget.value
                          if (IsAclInheritance(Scope)) SetPresetScope(Scope)
                        }}
                      >
                        {AclScopeOptions.map((Scope) => (
                          <option key={Scope} value={Scope}>
                            {ScopeLabel(Scope)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <div>
                      {Object.entries(AclPresets).map(([Name, Actions]) =>
                        Actions.every((Action) => Collection.SupportedActions.includes(Action)) ? (
                          <Button
                            key={Name}
                            onClick={() => {
                              ApplyPreset(Actions)
                            }}
                          >
                            {Name}
                          </Button>
                        ) : null,
                      )}
                    </div>
                    <p className='fb-muted'>{En.aclPresetExplanation}</p>
                  </fieldset>

                  <fieldset disabled={Saving}>
                    <legend>{En.aclDraftRules}</legend>
                    {Draft.length === 0 ? <p className='fb-muted'>{En.aclEmptyDraft}</p> : null}
                    <div className='fb-acl-draft'>
                      {Draft.map((Rule) => (
                        <div className='fb-acl-draft-row' key={Rule.Action}>
                          <strong>{ActionLabel(Rule.Action)}</strong>
                          <label>
                            {En.aclEffect}
                            <select
                              value={Rule.Effect}
                              onChange={(Event) => {
                                const Effect = Event.currentTarget.value
                                if (Effect !== 'allow' && Effect !== 'deny') return
                                SetDraft((Current) =>
                                  Current.map((Item) =>
                                    Item.Action === Rule.Action ? { ...Item, Effect } : Item,
                                  ),
                                )
                              }}
                            >
                              <option value='allow'>{En.aclAllow}</option>
                              <option value='deny'>{En.aclDeny}</option>
                            </select>
                          </label>
                          <label>
                            {En.aclScope}
                            <select
                              value={Rule.Inheritance}
                              onChange={(Event) => {
                                const Inheritance = Event.currentTarget.value
                                if (!IsAclInheritance(Inheritance)) return
                                SetDraft((Current) =>
                                  Current.map((Item) =>
                                    Item.Action === Rule.Action ? { ...Item, Inheritance } : Item,
                                  ),
                                )
                              }}
                            >
                              {AclScopeOptions.map((Scope) => (
                                <option key={Scope} value={Scope}>
                                  {ScopeLabel(Scope)}
                                </option>
                              ))}
                            </select>
                          </label>
                          <Button
                            aria-label={En.aclRemoveRule(ActionLabel(Rule.Action))}
                            appearance='subtle'
                            icon={<Trash2 />}
                            onClick={() => {
                              SetDraft((Current) =>
                                Current.filter(({ Action }) => Action !== Rule.Action),
                              )
                            }}
                          />
                        </div>
                      ))}
                    </div>
                    <div className='fb-acl-add-rule'>
                      <label>
                        {En.aclAction}
                        <select
                          disabled={MissingActions.length === 0}
                          value={NewAction}
                          onChange={(Event) => {
                            const Action = Event.currentTarget.value
                            if (Action === '' || IsAclAction(Collection.SupportedActions, Action))
                              SetNewAction(Action)
                          }}
                        >
                          <option value=''>{En.aclChooseAction}</option>
                          {MissingActions.map((Action) => (
                            <option key={Action} value={Action}>
                              {ActionLabel(Action)}
                            </option>
                          ))}
                        </select>
                      </label>
                      <Button
                        disabled={NewAction === ''}
                        icon={<Plus />}
                        onClick={() => {
                          if (NewAction === '') return
                          SetDraft((Current) => [
                            ...Current,
                            { Action: NewAction, Effect: 'allow', Inheritance: 'self' },
                          ])
                          SetNewAction('')
                        }}
                      >
                        {En.aclAddRule}
                      </Button>
                    </div>
                  </fieldset>
                </section>
              </>
            )}
          </DialogContent>
          <DialogActions>
            <Button appearance='secondary' disabled={Saving} onClick={OnClose}>
              {En.close}
            </Button>
            <Button appearance='primary' disabled={!CanSave} onClick={() => void Save()}>
              {Saving ? En.aclSaving : En.save}
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  )
}

function PrincipalSelector(Kind: AclPrincipalKind, Value: string): AclPrincipalSelector | null {
  const Exact = Value.trim()
  if (Kind === 'user') {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(Exact)) return null
    return { GroupId: null, Kind, VerifiedEmail: Exact }
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(Exact))
    return null
  return { GroupId: Exact, Kind, VerifiedEmail: null }
}

function IsAclAction(Actions: readonly AclAction[], Value: string): Value is AclAction {
  return Actions.some((Action) => Action === Value)
}

function IsAclInheritance(Value: string): Value is AclInheritance {
  return AclScopeOptions.some((Scope) => Scope === Value)
}

function ActionLabel(Action: AclAction): string {
  return Action.toLocaleLowerCase()
    .split('_')
    .map((Part) => `${Part.charAt(0).toLocaleUpperCase()}${Part.slice(1)}`)
    .join(' ')
}

function EffectLabel(Effect: 'allow' | 'deny'): string {
  return Effect === 'allow' ? En.aclAllow : En.aclDeny
}

function ScopeLabel(Scope: AclInheritance): string {
  if (Scope === 'self') return En.aclScopeSelf
  if (Scope === 'children') return En.aclScopeChildren
  if (Scope === 'descendants') return En.aclScopeDescendants
  return En.aclScopeSelfAndDescendants
}

function SourceLabel(Source: AclEntry['Source']): string {
  if (Source === 'core') return En.aclSourceCore
  if (Source === 'share') return En.aclSourceShare
  return En.aclSourceNfs
}
