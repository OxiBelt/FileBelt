// SPDX-License-Identifier: Apache-2.0

import { Button, Spinner } from '@fluentui/react-components'
import { Download as DownloadIcon, FileCheck2, ShieldCheck } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'

import { BidiText, BrandMark, FileBeltIcon, FileBeltProvider } from '@filebelt/design-system'

import type { PublicShareClient, PublicShareGrant } from './client.js'
import { En } from './strings.js'
import { HasDevelopmentMockMarker, InternalNavigationHref } from './navigation.js'

function FormatBytes(Value: number): string {
  return new Intl.NumberFormat(undefined, {
    maximumFractionDigits: 1,
    notation: 'compact',
    style: 'unit',
    unit: 'byte',
    unitDisplay: 'narrow',
  }).format(Value)
}

export function ParsePublicShareFragment(Fragment: string): string {
  const Value = Fragment.startsWith('#') ? Fragment.slice(1) : Fragment
  const Parameters = new URLSearchParams(Value)
  return Parameters.get('token') ?? Value
}

export function TakePublicShareFragment(): string {
  const Fragment = window.location.hash
  const DevelopmentMock = import.meta.env.DEV && HasDevelopmentMockMarker(window.location.search)
  window.history.replaceState(
    {},
    '',
    InternalNavigationHref(window.location.pathname, DevelopmentMock),
  )
  return ParsePublicShareFragment(Fragment)
}

export function PublicShareApp({
  Client,
  FragmentToken,
}: Readonly<{
  Client: Readonly<PublicShareClient>
  FragmentToken: string
}>): ReactNode {
  const [Grant, SetGrant] = useState<PublicShareGrant | null>(null)
  const [Error, SetError] = useState<string | null>(null)
  const [Busy, SetBusy] = useState(true)
  const ExchangeStarted = useRef(false)

  useEffect(() => {
    if (ExchangeStarted.current) return
    ExchangeStarted.current = true
    if (FragmentToken.length === 0) {
      SetError(En.publicExpired)
      SetBusy(false)
      return
    }
    void Client.ExchangePublicShare(FragmentToken)
      .then(SetGrant)
      .catch(() => {
        SetError(En.publicExpired)
      })
      .finally(() => {
        SetBusy(false)
      })
  }, [Client, FragmentToken])

  const Download = async (): Promise<void> => {
    if (Grant === null) return
    SetBusy(true)
    try {
      const Url = URL.createObjectURL(await Client.DownloadPublic(Grant.ExchangeId))
      const Anchor = document.createElement('a')
      Anchor.download = Grant.Name
      Anchor.href = Url
      Anchor.click()
      URL.revokeObjectURL(Url)
    } finally {
      SetBusy(false)
    }
  }

  return (
    <FileBeltProvider Density='comfortable' ThemeChoice='system'>
      <main className='fb-public-shell'>
        <div className='fb-public-brand'>
          <BrandMark />
          <span>{En.appName}</span>
        </div>
        <section aria-labelledby='public-share-heading' className='fb-public-card'>
          <div className='fb-public-icon'>
            <FileBeltIcon Icon={Grant === null ? ShieldCheck : FileCheck2} size={36} />
          </div>
          <p className='fb-eyebrow'>{En.publicShare}</p>
          <h1 id='public-share-heading'>
            {Busy && Grant === null ? (
              En.publicLoading
            ) : Grant === null ? (
              En.publicExpired
            ) : (
              <BidiText>{Grant.Name}</BidiText>
            )}
          </h1>
          {Busy && Grant === null ? <Spinner label={En.publicLoading} /> : null}
          {Error === null ? null : (
            <p className='fb-error' role='alert'>
              {Error}
            </p>
          )}
          {Grant === null ? null : (
            <>
              <p className='fb-muted'>
                {FormatBytes(Grant.Size)} · expires{' '}
                <time dateTime={Grant.ExpiresAt}>
                  {new Intl.DateTimeFormat(undefined, {
                    dateStyle: 'medium',
                    timeStyle: 'short',
                  }).format(new Date(Grant.ExpiresAt))}
                </time>
              </p>
              <Button
                appearance='primary'
                disabled={Busy}
                icon={<DownloadIcon />}
                onClick={() => void Download()}
              >
                {En.publicDownload}
              </Button>
            </>
          )}
          <p className='fb-public-notice'>
            <FileBeltIcon Icon={ShieldCheck} size={16} /> {En.publicShareNotice}
          </p>
        </section>
      </main>
    </FileBeltProvider>
  )
}
