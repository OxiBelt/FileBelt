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

const fileBeltBrand: BrandVariants = {
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

const lightTheme = createLightTheme(fileBeltBrand);
const darkTheme = createDarkTheme(fileBeltBrand);

export function resolveTheme(
  choice: ThemeChoice,
  systemPrefersDark: boolean,
): ResolvedTheme {
  return choice === "system" ? (systemPrefersDark ? "dark" : "light") : choice;
}

function useSystemTheme(): boolean {
  const [prefersDark, setPrefersDark] = useState(() =>
    typeof window === "undefined"
      ? false
      : window.matchMedia("(prefers-color-scheme: dark)").matches,
  );

  useEffect(() => {
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const update = (): void => setPrefersDark(query.matches);
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);

  return prefersDark;
}

export interface FileBeltProviderProps extends PropsWithChildren {
  density: Density;
  themeChoice: ThemeChoice;
}

export function FileBeltProvider({
  children,
  density,
  themeChoice,
}: FileBeltProviderProps): ReactNode {
  const systemPrefersDark = useSystemTheme();
  const resolved = resolveTheme(themeChoice, systemPrefersDark);
  const theme = useMemo<Theme>(
    () => (resolved === "dark" ? darkTheme : lightTheme),
    [resolved],
  );

  useEffect(() => {
    document.documentElement.dataset.theme = resolved;
    document.documentElement.dataset.density = density;
    document.documentElement.style.colorScheme = resolved;
  }, [density, resolved]);

  return (
    <FluentProvider theme={theme} className="fb-provider">
      {children}
    </FluentProvider>
  );
}

export interface FileBeltIconProps extends Omit<LucideProps, "ref"> {
  icon: LucideIcon;
  label?: string;
}

export function FileBeltIcon({
  icon: Icon,
  label,
  size = 20,
  strokeWidth = 1.75,
  ...props
}: FileBeltIconProps): ReactNode {
  return (
    <Icon
      {...props}
      aria-hidden={label === undefined ? true : undefined}
      aria-label={label}
      role={label === undefined ? undefined : "img"}
      size={size}
      strokeWidth={strokeWidth}
    />
  );
}

export interface BidiTextProps {
  children: string;
  className?: string;
  title?: string;
}

export function BidiText({ children, className, title }: BidiTextProps): ReactNode {
  return (
    <bdi className={className} dir="auto" title={title}>
      {children}
    </bdi>
  );
}

export interface StatusPillProps {
  children: ReactNode;
  kind?: "brand" | "danger" | "informative" | "subtle" | "success" | "warning";
}

export function StatusPill({ children, kind = "subtle" }: StatusPillProps): ReactNode {
  return (
    <Badge appearance="tint" color={kind} size="small">
      {children}
    </Badge>
  );
}

export interface BrandMarkProps {
  className?: string;
  label?: string;
}

/** Original FileBelt mark: a secured file folded through a belt-like horizon. */
export function BrandMark({ className, label }: BrandMarkProps): ReactNode {
  return (
    <svg
      aria-hidden={label === undefined ? true : undefined}
      aria-label={label}
      className={mergeClasses("fb-brand-mark", className)}
      fill="none"
      role={label === undefined ? undefined : "img"}
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

export const visuallyHiddenStyle: CSSProperties = {
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
