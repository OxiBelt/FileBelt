// SPDX-License-Identifier: Apache-2.0

import {
  Badge,
  FluentProvider,
  createDarkTheme,
  createLightTheme,
  mergeClasses,
} from "@fluentui/react-components";
import type { BrandVariants, Theme } from "@fluentui/react-components";
import type { LucideIcon, LucideProps } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { CSSProperties, PropsWithChildren, ReactNode } from "react";

export type ThemeChoice = "system" | "light" | "dark";
export type ResolvedTheme = Exclude<ThemeChoice, "system">;
export type Density = "comfortable" | "compact";

const FileBeltBrand: BrandVariants = {
  10: "#02050a",
  20: "#0b1727",
  30: "#102842",
  40: "#153a5f",
  50: "#1c4c7c",
  60: "#265f99",
  70: "#3472b5",
  80: "#4586cf",
  90: "#5d9ae3",
  100: "#78a9ff",
  110: "#91b9ff",
  120: "#a6c8ff",
  130: "#bfd7ff",
  140: "#d5e5ff",
  150: "#e9f1ff",
  160: "#f7faff",
};

const LightTheme = createLightTheme(FileBeltBrand);
const DarkTheme = createDarkTheme(FileBeltBrand);

export function ResolveTheme(
  Choice: ThemeChoice,
  SystemPrefersDark: boolean,
): ResolvedTheme {
  return Choice === "system" ? (SystemPrefersDark ? "dark" : "light") : Choice;
}

function useSystemTheme(): boolean {
  const [PrefersDark, SetPrefersDark] = useState(() =>
    typeof window === "undefined"
      ? false
      : window.matchMedia("(prefers-color-scheme: dark)").matches,
  );

  useEffect(() => {
    const Query = window.matchMedia("(prefers-color-scheme: dark)");
    const Update = (): void => SetPrefersDark(Query.matches);
    Query.addEventListener("change", Update);
    return () => Query.removeEventListener("change", Update);
  }, []);

  return PrefersDark;
}

export interface FileBeltProviderProps extends PropsWithChildren {
  Density: Density;
  ThemeChoice: ThemeChoice;
}

export function FileBeltProvider({
  children: Children,
  Density,
  ThemeChoice,
}: FileBeltProviderProps): ReactNode {
  const SystemPrefersDark = useSystemTheme();
  const Resolved = ResolveTheme(ThemeChoice, SystemPrefersDark);
  const Theme = useMemo<Theme>(
    () => (Resolved === "dark" ? DarkTheme : LightTheme),
    [Resolved],
  );

  useEffect(() => {
    document.documentElement.dataset.theme = Resolved;
    document.documentElement.dataset.density = Density;
    document.documentElement.style.colorScheme = Resolved;
  }, [Density, Resolved]);

  return (
    <FluentProvider theme={Theme} className="fb-provider">
      {Children}
    </FluentProvider>
  );
}

export interface FileBeltIconProps extends Omit<LucideProps, "ref"> {
  Icon: LucideIcon;
  Label?: string;
}

export function FileBeltIcon({
  Icon,
  Label,
  size: Size = 20,
  strokeWidth: StrokeWidth = 1.75,
  ...Props
}: FileBeltIconProps): ReactNode {
  return (
    <Icon
      {...Props}
      aria-hidden={Label === undefined ? true : undefined}
      aria-label={Label}
      role={Label === undefined ? undefined : "img"}
      size={Size}
      strokeWidth={StrokeWidth}
    />
  );
}

export interface BidiTextProps {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- React reserves `children` for nested JSX content.
  children: string;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- This component forwards the DOM `className` contract.
  className?: string;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- This component forwards the DOM `title` contract.
  title?: string;
}

export function BidiText({ children: Children, className: ClassName, title: Title }: BidiTextProps): ReactNode {
  return (
    <bdi className={ClassName} dir="auto" title={Title}>
      {Children}
    </bdi>
  );
}

export interface StatusPillProps {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- React reserves `children` for nested JSX content.
  children: ReactNode;
  Kind?: "brand" | "danger" | "informative" | "subtle" | "success" | "warning";
}

export function StatusPill({ children: Children, Kind = "subtle" }: StatusPillProps): ReactNode {
  return (
    <Badge appearance="tint" color={Kind} size="small">
      {Children}
    </Badge>
  );
}

export interface BrandMarkProps {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- This component forwards the DOM `className` contract.
  className?: string;
  Label?: string;
}

/** Original FileBelt mark: a secured file folded through a belt-like horizon. */
export function BrandMark({ className: ClassName, Label }: BrandMarkProps): ReactNode {
  return (
    <svg
      aria-hidden={Label === undefined ? true : undefined}
      aria-label={Label}
      className={mergeClasses("fb-brand-mark", ClassName)}
      fill="none"
      role={Label === undefined ? undefined : "img"}
      viewBox="0 0 36 36"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M9 4.5h12l6 6V29a2.5 2.5 0 0 1-2.5 2.5h-15A2.5 2.5 0 0 1 7 29V7a2.5 2.5 0 0 1 2-2.45Z"
        stroke="currentColor"
        strokeLinejoin="round"
        strokeWidth="2"
      />
      <path d="M21 4.8V11h6" stroke="currentColor" strokeLinejoin="round" strokeWidth="2" />
      <path d="M4 20.5h28" stroke="currentColor" strokeLinecap="round" strokeWidth="5" />
      <path d="M5 20.5h26" stroke="var(--fb-brand-cut, #121212)" strokeDasharray="2.5 3" strokeLinecap="round" strokeWidth="1.5" />
    </svg>
  );
}

export const VisuallyHiddenStyle: CSSProperties = {
  border: 0,
  clip: "rect(0 0 0 0)",
  clipPath: "inset(50%)",
  height: "1px",
  margin: "-1px",
  overflow: "hidden",
  padding: 0,
  position: "absolute",
  whiteSpace: "nowrap",
  width: "1px",
};
