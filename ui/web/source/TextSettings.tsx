// SPDX-License-Identifier: Apache-2.0

import { Button, Select, Spinner } from '@fluentui/react-components'
import { useCallback, useEffect, useState, type ReactNode } from 'react'

import type {
  EditTextLimitBytes,
  FileBeltClient,
  InlineTextLimitBytes,
  TextPreferences,
} from './client.js'
import { ApiRequestError } from './http-client.js'

const MiB = 1024 * 1024
const EditOptions: readonly EditTextLimitBytes[] = [
  1_048_576, 2_097_152, 4_194_304, 8_388_608, 16_777_216,
]
const InlineOptions: readonly InlineTextLimitBytes[] = [
  8_388_608, 16_777_216, 33_554_432, 67_108_864, 104_857_600,
]

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- React owns the client prop and this component only invokes its receiver-free methods.
export function TextSettings({ Client }: { Client: FileBeltClient }): ReactNode {
  const [Etag, SetEtag] = useState<string | null>(null)
  const [Value, SetValue] = useState<TextPreferences | null>(null)
  const [ErrorMessage, SetError] = useState<string | null>(null)
  const [Loading, SetLoading] = useState(true)
  const [Saving, SetSaving] = useState(false)
  const Load = useCallback(
    async (PreserveDraft = false): Promise<void> => {
      SetLoading(true)
      try {
        const Response = await Client.GetTextPreferences()
        SetEtag(Response.Etag)
        if (!PreserveDraft) SetValue(Response.Value)
        SetError(null)
      } catch (Cause) {
        SetError(Cause instanceof Error ? Cause.message : 'Text preferences are unavailable.')
      } finally {
        SetLoading(false)
      }
    },
    [Client],
  )

  useEffect(() => {
    void Load()
  }, [Load])

  const Save = async (): Promise<void> => {
    if (Etag === null || Value === null) return
    SetSaving(true)
    SetError(null)
    try {
      const Response = await Client.UpdateTextPreferences(Value, Etag)
      SetEtag(Response.Etag)
      SetValue(Response.Value)
    } catch (Cause) {
      if (Cause instanceof ApiRequestError && (Cause.Status === 409 || Cause.Status === 412)) {
        await Load(true)
        SetError('Text preferences changed elsewhere. Review your draft and save it again.')
      } else {
        SetError(Cause instanceof Error ? Cause.message : 'Text preferences could not be saved.')
      }
    } finally {
      SetSaving(false)
    }
  }

  return (
    <section aria-labelledby='text-settings-heading' className='fb-text-settings'>
      <header className='fb-page-heading'>
        <div>
          <h1 id='text-settings-heading'>Text editing</h1>
          <p className='fb-muted'>
            Choose personal source and inline viewing limits. The server enforces these limits for
            every request.
          </p>
        </div>
      </header>
      {ErrorMessage === null ? null : <p role='alert'>{ErrorMessage}</p>}
      {Loading ? <Spinner label='Loading text preferences' /> : null}
      {!Loading && Value === null ? (
        <Button onClick={() => void Load()}>Retry loading text preferences</Button>
      ) : null}
      {Value === null ? null : (
        <form
          onSubmit={(Event) => {
            Event.preventDefault()
            void Save()
          }}
        >
          <label htmlFor='text-edit-limit'>
            Editable source limit
            <Select
              id='text-edit-limit'
              onChange={(Event) => {
                const EditLimitBytes = Number(Event.currentTarget.value)
                if (!IsEditLimit(EditLimitBytes)) return
                SetValue((Current) =>
                  Current === null
                    ? Current
                    : {
                        ...Current,
                        EditLimitBytes,
                        InlineLimitBytes:
                          InlineOptions.find(
                            (Candidate) =>
                              Candidate >= Current.InlineLimitBytes && Candidate >= EditLimitBytes,
                          ) ?? 104_857_600,
                      },
                )
              }}
              value={String(Value.EditLimitBytes)}
            >
              {EditOptions.map((Bytes) => (
                <option key={Bytes} value={Bytes}>
                  {Bytes / MiB} MiB
                </option>
              ))}
            </Select>
          </label>
          <label htmlFor='text-inline-limit'>
            Inline source limit
            <Select
              id='text-inline-limit'
              onChange={(Event) => {
                const InlineLimitBytes = Number(Event.currentTarget.value)
                if (!IsInlineLimit(InlineLimitBytes)) return
                SetValue((Current) =>
                  Current === null
                    ? Current
                    : {
                        ...Current,
                        InlineLimitBytes,
                      },
                )
              }}
              value={String(Value.InlineLimitBytes)}
            >
              {InlineOptions.filter((Bytes) => Bytes >= Value.EditLimitBytes).map((Bytes) => (
                <option key={Bytes} value={Bytes}>
                  {Bytes / MiB} MiB
                </option>
              ))}
            </Select>
          </label>
          <Button appearance='primary' disabled={Saving} type='submit'>
            {Saving ? 'Saving…' : 'Save text limits'}
          </Button>
        </form>
      )}
    </section>
  )
}

function IsEditLimit(Value: number): Value is EditTextLimitBytes {
  return EditOptions.some((Candidate) => Candidate === Value)
}

function IsInlineLimit(Value: number): Value is InlineTextLimitBytes {
  return InlineOptions.some((Candidate) => Candidate === Value)
}
