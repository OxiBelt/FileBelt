// SPDX-License-Identifier: Apache-2.0

export function HasDevelopmentMockMarker(Search: string): boolean {
  return new URLSearchParams(Search)
    .getAll('filebelt-development')
    .some((Value) => Value === 'mock')
}

export function InternalNavigationHref(Path: string, DevelopmentMock: boolean): string {
  const Pathname = Path.split(/[?#]/, 1)[0] ?? '/drive'
  return DevelopmentMock ? `${Pathname}?filebelt-development=mock` : Pathname
}
