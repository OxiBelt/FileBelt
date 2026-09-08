// SPDX-License-Identifier: Apache-2.0
// Exercises the Markdown editor through the browser without an application route.

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { expect, test } from '@playwright/test'
import { createServer as CreateViteServer } from 'vite'

const MarkdownRoot = resolve(import.meta.dirname, '../../markdown')
const RepositoryRoot = resolve(MarkdownRoot, '../..')
const FixtureModule = join(MarkdownRoot, '__editor_fixture.jsx')
let CacheDirectory = ''
let FixtureOrigin = ''
let ViteServer

test.use({ trace: 'off' })

test.beforeAll(async () => {
  CacheDirectory = await mkdtemp(join(tmpdir(), 'filebelt-editor-state-'))
  ViteServer = await CreateViteServer({
    cacheDir: join(CacheDirectory, 'vite-cache'),
    configFile: false,
    optimizeDeps: {
      include: [
        'react',
        'react/jsx-runtime',
        'react/jsx-dev-runtime',
        'react-dom/client',
        'react-dom',
        'yjs',
        'y-protocols/awareness',
        'y-codemirror.next',
        '@codemirror/view',
        '@codemirror/state',
        '@codemirror/commands',
      ],
      noDiscovery: true,
    },
    plugins: [
      {
        load(Id) {
          if (Id !== FixtureModule) return undefined
          return FixtureSource()
        },
        name: 'filebelt-editor-state-fixture',
        resolveId(Id) {
          return Id === '/__editor_fixture.jsx' ? FixtureModule : undefined
        },
        configureServer(Server) {
          Server.middlewares.use((Request, Response, Next) => {
            if (Request.url !== '/') return Next()
            Response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
            Response.end(
              '<!doctype html><div id="root"></div><script type="module" src="/__editor_fixture.jsx"></script>',
            )
          })
        },
      },
    ],
    root: MarkdownRoot,
    server: {
      fs: { allow: [RepositoryRoot] },
      host: '127.0.0.1',
      hmr: false,
      port: 0,
    },
  })
  await ViteServer.listen()
  const Address = ViteServer.httpServer?.address()
  if (Address === null || Address === undefined || typeof Address === 'string')
    throw new Error('Fixture did not bind a TCP port.')
  FixtureOrigin = `http://127.0.0.1:${Address.port}`
})

test.afterAll(async () => {
  await ViteServer?.close()
  await rm(CacheDirectory, { force: true, recursive: true })
})

test.beforeEach(async ({ page: Page }) => {
  await Page.goto(FixtureOrigin)
  await expect.poll(() => Page.evaluate(() => globalThis.EditorFixture !== undefined)).toBe(true)
})

test('does not let a stale React echo overwrite two immediate collaborative edits', async ({
  page: Page,
}) => {
  await Page.evaluate(() => globalThis.EditorFixture.AttachLive('base'))
  await Page.evaluate(() => globalThis.EditorFixture.DispatchText('basea'))
  await Page.evaluate(() => globalThis.EditorFixture.DispatchText('baseai'))
  await expect
    .poll(() => Page.evaluate(() => globalThis.EditorFixture.State()))
    .toMatchObject({
      SharedText: 'baseai',
      ViewText: 'baseai',
    })

  await Page.evaluate(() => globalThis.EditorFixture.ResetUpdates())
  await Page.evaluate(() => globalThis.EditorFixture.ReplaceSourceText('basea'))
  await expect
    .poll(() => Page.evaluate(() => globalThis.EditorFixture.State()))
    .toEqual({
      SharedText: 'baseai',
      ViewText: 'baseai',
      Updates: 0,
    })
})

test('keeps a remote Yjs update when React repeats its stale source', async ({ page: Page }) => {
  await Page.evaluate(() => globalThis.EditorFixture.AttachLive('base'))
  await Page.evaluate(() => globalThis.EditorFixture.ApplyRemoteText('remote'))
  await expect
    .poll(() => Page.evaluate(() => globalThis.EditorFixture.State()))
    .toMatchObject({
      SharedText: 'remote',
      ViewText: 'remote',
    })

  await Page.evaluate(() => globalThis.EditorFixture.ResetUpdates())
  await Page.evaluate(() => globalThis.EditorFixture.ReplaceSourceText('base'))
  await expect
    .poll(() => Page.evaluate(() => globalThis.EditorFixture.State()))
    .toEqual({
      SharedText: 'remote',
      ViewText: 'remote',
      Updates: 0,
    })
})

test('reflects intentional live Yjs replacement in CodeMirror', async ({ page: Page }) => {
  await Page.evaluate(() => globalThis.EditorFixture.AttachLive('base'))
  await Page.evaluate(() => globalThis.EditorFixture.ReplaceLiveText('live replacement'))
  await expect
    .poll(() => Page.evaluate(() => globalThis.EditorFixture.State()))
    .toMatchObject({
      SharedText: 'live replacement',
      ViewText: 'live replacement',
    })
})

test('restores the current fallback source after a live document detaches', async ({
  page: Page,
}) => {
  await Page.evaluate(() => globalThis.EditorFixture.MountFallback('initial'))
  await Page.evaluate(() => globalThis.EditorFixture.ReplaceSourceText('fallback current'))
  await expect
    .poll(() => Page.evaluate(() => globalThis.EditorFixture.State()))
    .toMatchObject({
      ViewText: 'fallback current',
    })

  await Page.evaluate(() => globalThis.EditorFixture.AttachLive('live'))
  await Page.evaluate(() => globalThis.EditorFixture.DetachLive())
  await expect
    .poll(() => Page.evaluate(() => globalThis.EditorFixture.State()))
    .toMatchObject({
      ViewText: 'fallback current',
    })
})

test('applies replacement source props while the fallback owns its document', async ({
  page: Page,
}) => {
  await Page.evaluate(() => globalThis.EditorFixture.MountFallback('before'))
  await Page.evaluate(() => globalThis.EditorFixture.ReplaceSourceText('after'))
  await expect
    .poll(() => Page.evaluate(() => globalThis.EditorFixture.State()))
    .toMatchObject({
      ViewText: 'after',
    })
})

function FixtureSource() {
  return String.raw`
    import React from 'react'
    import { createRoot } from 'react-dom/client'
    import { flushSync } from 'react-dom'
    import { EditorView } from '@codemirror/view'
    import { Awareness } from 'y-protocols/awareness'
    import * as Y from 'yjs'
    import { TextSourceEditor } from './source/editor.tsx'

    const Root = createRoot(document.querySelector('#root'))
    let Collaboration
    let LiveDocument
    let SourceText = ''
    let Updates = 0

    function Render() {
      flushSync(() => {
        Root.render(
          <TextSourceEditor
            {...(Collaboration === undefined ? {} : { Collaboration })}
            Source={{ HasByteOrderMark: false, LineEnding: 'lf', Text: SourceText }}
            SourceEditorLabel='Test source editor'
          />,
        )
      })
    }

    function View() {
      const Content = document.querySelector('.cm-content')
      if (Content === null) throw new Error('CodeMirror did not mount.')
      const Result = EditorView.findFromDOM(Content)
      if (Result === null) throw new Error('CodeMirror view was not found.')
      return Result
    }

    function State() {
      return {
        SharedText: Collaboration?.Document.getText(Collaboration.TextName).toString(),
        ViewText: View().state.doc.toString(),
        Updates,
      }
    }

    globalThis.EditorFixture = {
      ApplyRemoteText(Text) {
        if (Collaboration === undefined || LiveDocument === undefined)
          throw new Error('A live document is required.')
        const RemoteDocument = new Y.Doc()
        Y.applyUpdate(RemoteDocument, Y.encodeStateAsUpdate(LiveDocument))
        const RemoteText = RemoteDocument.getText(Collaboration.TextName)
        RemoteText.delete(0, RemoteText.length)
        RemoteText.insert(0, Text)
        Y.applyUpdate(
          LiveDocument,
          Y.encodeStateAsUpdate(RemoteDocument, Y.encodeStateVector(LiveDocument)),
        )
        RemoteDocument.destroy()
      },
      AttachLive(Text) {
        LiveDocument?.destroy()
        LiveDocument = new Y.Doc()
        LiveDocument.on('update', () => { Updates += 1 })
        const SharedText = LiveDocument.getText('markdown')
        SharedText.insert(0, Text)
        Collaboration = {
          Awareness: new Awareness(LiveDocument),
          Document: LiveDocument,
          TextName: 'markdown',
        }
        Render()
      },
      DetachLive() {
        Collaboration?.Awareness.destroy()
        LiveDocument?.destroy()
        Collaboration = undefined
        LiveDocument = undefined
        Render()
      },
      DispatchText(Text) {
        const CurrentView = View()
        CurrentView.dispatch({
          changes: { from: 0, insert: Text, to: CurrentView.state.doc.length },
        })
      },
      MountFallback(Text) {
        Collaboration?.Awareness.destroy()
        LiveDocument?.destroy()
        Collaboration = undefined
        LiveDocument = undefined
        SourceText = Text
        Render()
      },
      ReplaceLiveText(Text) {
        if (Collaboration === undefined) throw new Error('A live document is required.')
        const SharedText = Collaboration.Document.getText(Collaboration.TextName)
        SharedText.delete(0, SharedText.length)
        SharedText.insert(0, Text)
      },
      ReplaceSourceText(Text) {
        SourceText = Text
        Render()
      },
      ResetUpdates() {
        Updates = 0
      },
      State,
    }
  `
}
