// Inline SVG icons. The paths are from Lucide (https://lucide.dev, ISC licence, Copyright (c) Lucide Contributors),
// 24x24, stroke only. Inline so the app needs no network and no icon font. `BrandMark` is the Sparrow mark.
import type { ReactNode } from "react";

const PATHS = {
  user: (
    <>
      <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </>
  ),
  globe: (
    <>
      <circle cx="12" cy="12" r="10" />
      <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
      <path d="M2 12h20" />
    </>
  ),
  key: (
    <>
      <path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4" />
      <path d="m21 2-9.6 9.6" />
      <circle cx="7.5" cy="15.5" r="5.5" />
    </>
  ),
  monitor: (
    <>
      <rect width="20" height="14" x="2" y="3" rx="2" />
      <path d="M8 21h8" />
      <path d="M12 17v4" />
    </>
  ),
  search: (
    <>
      <path d="m21 21-4.34-4.34" />
      <circle cx="11" cy="11" r="8" />
    </>
  ),
  external: (
    <>
      <path d="M15 3h6v6" />
      <path d="M10 14 21 3" />
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
    </>
  ),
  x: (
    <>
      <path d="M18 6 6 18" />
      <path d="m6 6 12 12" />
    </>
  ),
  download: (
    <>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="m7 10 5 5 5-5" />
      <path d="M12 15V3" />
    </>
  ),
  upload: (
    <>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="m17 8-5-5-5 5" />
      <path d="M12 3v12" />
    </>
  ),
  filter: <path d="M22 3H2l8 9.46V19l4 2v-8.54z" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="10" />
      <path d="M12 6v6l4 2" />
    </>
  ),
  alert: (
    <>
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </>
  ),
  check: <path d="M20 6 9 17l-5-5" />,
  "chevron-down": <path d="m6 9 6 6 6-6" />,
  "chevron-right": <path d="m9 18 6-6-6-6" />,
  plus: (
    <>
      <path d="M5 12h14" />
      <path d="M12 5v14" />
    </>
  ),
  flag: (
    <>
      <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z" />
      <path d="M4 22v-7" />
    </>
  ),
  note: (
    <>
      <path d="M16 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V8z" />
      <path d="M15 3v4a2 2 0 0 0 2 2h4" />
    </>
  ),
  tag: (
    <>
      <path d="M12.586 2.586A2 2 0 0 0 11.172 2H4a2 2 0 0 0-2 2v7.172a2 2 0 0 0 .586 1.414l8.704 8.704a2.426 2.426 0 0 0 3.42 0l6.58-6.58a2.426 2.426 0 0 0 0-3.42z" />
      <circle cx="7.5" cy="7.5" r=".5" fill="currentColor" />
    </>
  ),
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

/** Decorative by default (aria-hidden): the control around it carries the accessible name. */
export default function Icon({ name, size = 14 }: { name: IconName; size?: number }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}

export function BrandMark({ size = 18 }: { size?: number }) {
  return (
    <svg className="icon brand-mark" width={size} height={(size * 16.14) / 18} viewBox="0 0.43 18 16.14" aria-hidden="true" focusable="false">
      <path
        fill="currentColor"
        d="M13.03,4.47 C13.03,4.98 12.61,5.4 12.1,5.4 C11.59,5.4 11.17,4.98 11.17,4.47 C11.17,3.96 11.59,3.53 12.1,3.53 C12.61,3.53 13.03,3.96 13.03,4.47 Z"
      />
      <path
        fill="currentColor"
        fillRule="evenodd"
        d="M18,5.4 C18,5.61 17.89,5.8 17.72,5.91 L16.14,6.97 L16.14,8.5 C16.14,12.95 12.52,16.57 8.07,16.57 L1.24,16.57 C0.76,16.57 0.33,16.3 0.12,15.87 C-0.09,15.44 -0.03,14.92 0.27,14.55 L0.28,14.54 L6.83,6.69 L6.83,5.16 C6.83,2.57 8.91,0.44 11.46,0.43 L11.48,0.43 C13.51,0.43 15.31,1.75 15.92,3.68 L17.72,4.88 C17.89,4.99 18,5.19 18,5.4 Z M15.04,4.59 L16.26,5.4 L15.17,6.12 C15,6.23 14.9,6.43 14.9,6.64 L14.9,8.5 C14.9,12.27 11.84,15.33 8.07,15.33 L4.95,15.33 L9.79,9.52 C9.94,9.35 9.98,9.11 9.9,8.9 C9.82,8.69 9.64,8.54 9.42,8.5 C9.2,8.46 8.97,8.54 8.83,8.72 L3.33,15.33 L1.24,15.33 L7.93,7.31 C8.02,7.2 8.07,7.06 8.07,6.91 L8.07,5.16 C8.07,3.25 9.6,1.68 11.47,1.67 L11.48,1.67 C13.03,1.67 14.4,2.73 14.79,4.23 C14.83,4.38 14.91,4.51 15.04,4.59 Z"
      />
    </svg>
  );
}
