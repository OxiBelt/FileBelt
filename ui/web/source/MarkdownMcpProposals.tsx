// SPDX-License-Identifier: Apache-2.0

import { Button, Field, Select, Spinner } from '@fluentui/react-components'
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import type {
  McpCapabilityReviewView,
  McpInvocationEventView,
  McpPreparedInvocation,
  McpRegistrationView,
  McpSettingsClient,
} from '@filebelt/mcp-settings'
import { En } from './strings.js'

interface MarkdownMcpProposalsProps {
  BaseVersionId: string
  Client: McpSettingsClient
  NodeId: string
  OnApply(Proposal: string, BaseText: string, InvocationId: string): boolean
  Selection: { End: number; Start: number }
  Source: string
}

interface Proposal {
  BaseText: string
  InvocationId: string
  Text: string
}

export interface PreparedRequestIdentity {
  BaseVersionId: string
  Fingerprint: string
  NodeId: string
  RegistrationId: string
  SelectionEnd: number
  SelectionStart: number
  Source: string
}

interface PreparedRequest extends PreparedRequestIdentity {
  Invocation: McpPreparedInvocation
}

export function IsPreparedRequestStale(
  Prepared: Readonly<PreparedRequestIdentity>,
  Current: Readonly<PreparedRequestIdentity>,
): boolean {
  return (
    Prepared.BaseVersionId !== Current.BaseVersionId ||
    Prepared.Fingerprint !== Current.Fingerprint ||
    Prepared.NodeId !== Current.NodeId ||
    Prepared.RegistrationId !== Current.RegistrationId ||
    Prepared.SelectionEnd !== Current.SelectionEnd ||
    Prepared.SelectionStart !== Current.SelectionStart ||
    Prepared.Source !== Current.Source
  )
}

// oxlint-disable typescript/prefer-readonly-parameter-types, typescript/unbound-method -- React owns nested props and the apply callback is a receiver-free parent function.
export function MarkdownMcpProposals({
  BaseVersionId,
  Client,
  NodeId,
  OnApply,
  Selection,
  Source,
}: MarkdownMcpProposalsProps): ReactNode {
  // oxlint-enable typescript/prefer-readonly-parameter-types, typescript/unbound-method
  const [Registrations, SetRegistrations] = useState<readonly McpRegistrationView[]>([])
  const [RegistrationId, SetRegistrationId] = useState('')
  const [Review, SetReview] = useState<McpCapabilityReviewView | null>(null)
  const [Fingerprint, SetFingerprint] = useState('')
  const [Prepared, SetPrepared] = useState<PreparedRequest | null>(null)
  const [Proposal, SetProposal] = useState<Proposal | null>(null)
  const [Busy, SetBusy] = useState(false)
  const [ErrorMessage, SetError] = useState<string | null>(null)
  const Selected = Registrations.find(({ Id }) => Id === RegistrationId)
  const Capabilities = useMemo(
    () =>
      Review?.Capabilities.filter(
        (Capability) => Review.Decisions[Capability.Fingerprint] === 'approved',
      ) ?? [],
    [Review],
  )
  const PreparedIsStale =
    Prepared !== null &&
    IsPreparedRequestStale(Prepared, {
      BaseVersionId,
      Fingerprint,
      NodeId,
      RegistrationId,
      SelectionEnd: Selection.End,
      SelectionStart: Selection.Start,
      Source,
    })

  useEffect(() => {
    let Active = true
    void Client.getSnapshot(false)
      .then((Snapshot) => {
        if (!Active) return
        SetRegistrations(Snapshot.Registrations)
        SetRegistrationId(
          Snapshot.Registrations.find(({ LifecycleState }) => LifecycleState === 'enabled')?.Id ??
            '',
        )
      })
      .catch(() => {
        if (Active) SetError(En.markdownMcpUnavailable)
      })
    return () => {
      Active = false
    }
  }, [Client])

  useEffect(() => {
    if (RegistrationId.length === 0) {
      SetReview(null)
      return undefined
    }
    let Active = true
    void Client.getCapabilityReview(RegistrationId)
      .then((Value) => {
        if (Active) SetReview(Value)
      })
      .catch(() => {
        if (Active) SetReview(null)
      })
    return () => {
      Active = false
    }
  }, [Client, RegistrationId])

  useEffect(() => {
    SetFingerprint(Capabilities[0]?.Fingerprint ?? '')
  }, [Capabilities])

  const Prepare = async (): Promise<void> => {
    const Capability = Capabilities.find((Value) => Value.Fingerprint === Fingerprint)
    if (Selected === undefined || Capability === undefined) return
    SetBusy(true)
    SetError(null)
    SetProposal(null)
    try {
      const Invocation = await Client.createInvocationIntent({
        ApplicationId: 'filebelt-web-markdown-proposal',
        Arguments: { selection: { end: Selection.End, start: Selection.Start } },
        Capability: {
          Fingerprint: Capability.Fingerprint,
          Kind: Capability.Kind,
          Name: Capability.Name,
        },
        RegistrationId: Selected.Id,
        SemanticInput: { BaseVersionId, Markdown: Source, NodeId },
      })
      SetPrepared({
        BaseVersionId,
        Fingerprint: Capability.Fingerprint,
        Invocation,
        NodeId,
        RegistrationId: Selected.Id,
        SelectionEnd: Selection.End,
        SelectionStart: Selection.Start,
        Source,
      })
    } catch (Cause) {
      SetError(Cause instanceof Error ? Cause.message : En.markdownMcpUnavailable)
    } finally {
      SetBusy(false)
    }
  }

  const Confirm = async (): Promise<void> => {
    if (Prepared === null || PreparedIsStale) return
    SetBusy(true)
    SetError(null)
    SetPrepared(null)
    const BaseText = Prepared.Invocation.Input.SemanticInput?.Markdown
    if (BaseText === undefined) {
      SetBusy(false)
      SetError(En.markdownMcpUnavailable)
      return
    }
    try {
      await Client.approveAndInvoke(
        Prepared.Invocation,
        // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The MCP client owns this discriminated event union and the callback only observes it.
        (Event: McpInvocationEventView) => {
          if (Event.Kind === 'semanticMarkdown')
            SetProposal({ BaseText, InvocationId: Event.InvocationId, Text: Event.Value.Markdown })
        },
      )
    } catch (Cause) {
      SetError(Cause instanceof Error ? Cause.message : En.markdownMcpUnavailable)
    } finally {
      SetBusy(false)
    }
  }

  const Apply = (): void => {
    if (Proposal === null) return
    if (!OnApply(Proposal.Text, Proposal.BaseText, Proposal.InvocationId))
      SetError(En.markdownProposalStale)
    else SetProposal(null)
  }

  return (
    <section aria-labelledby='markdown-mcp-heading' className='fb-markdown-proposals'>
      <h2 id='markdown-mcp-heading'>{En.markdownMcpHeading}</h2>
      <p className='fb-muted'>{En.markdownMcpNotice}</p>
      <Field label={En.markdownMcpServer}>
        <Select
          disabled={Busy}
          onChange={(Event) => {
            SetRegistrationId(Event.target.value)
          }}
          value={RegistrationId}
        >
          <option value=''>{En.markdownMcpSelect}</option>
          {Registrations.map((Registration) => (
            <option key={Registration.Id} value={Registration.Id}>
              {Registration.DisplayName}
            </option>
          ))}
        </Select>
      </Field>
      <Field label={En.markdownMcpCapability}>
        <Select
          disabled={Busy || RegistrationId.length === 0}
          onChange={(Event) => {
            SetFingerprint(Event.target.value)
          }}
          value={Fingerprint}
        >
          <option value=''>{En.markdownMcpSelect}</option>
          {Capabilities.map((Capability) => (
            <option key={Capability.Fingerprint} value={Capability.Fingerprint}>
              {Capability.Title ?? Capability.Name}
            </option>
          ))}
        </Select>
      </Field>
      <p className='fb-muted'>{En.markdownSelection(Selection.Start, Selection.End)}</p>
      <Button
        appearance='secondary'
        disabled={Busy || Fingerprint.length === 0}
        onClick={() => void Prepare()}
      >
        {En.markdownMcpPropose}
      </Button>
      {Prepared === null ? null : (
        <div className='fb-markdown-proposal-confirm'>
          <p>{En.markdownMcpConfirm}</p>
          {PreparedIsStale ? (
            <p className='fb-error' role='alert'>
              {En.markdownMcpConfirmationStale}
            </p>
          ) : null}
          <Button
            appearance='primary'
            disabled={Busy || PreparedIsStale}
            onClick={() => void Confirm()}
          >
            {En.markdownMcpConfirmButton}
          </Button>
          <Button
            disabled={Busy}
            onClick={() => {
              SetPrepared(null)
            }}
          >
            {En.close}
          </Button>
        </div>
      )}
      {Busy ? <Spinner label={En.working} size='tiny' /> : null}
      {ErrorMessage === null ? null : (
        <p className='fb-error' role='alert'>
          {ErrorMessage}
        </p>
      )}
      {Proposal === null ? null : (
        <section aria-label={En.markdownProposalPreview}>
          <h3>{En.markdownProposalPreview}</h3>
          <pre>{Proposal.Text}</pre>
          <Button appearance='primary' onClick={Apply}>
            {En.markdownProposalApply}
          </Button>
          <Button
            onClick={() => {
              SetProposal(null)
            }}
          >
            {En.close}
          </Button>
        </section>
      )}
    </section>
  )
}
