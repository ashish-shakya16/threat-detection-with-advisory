interface GuardMarkProps {
  className?: string;
}

/**
 * Custom guard-station mark: a shield built from a watch-tower silhouette,
 * not a generic lucide shield icon or gradient rounded-square logo tile.
 */
export function GuardMark({ className }: GuardMarkProps) {
  return (
    <svg viewBox="0 0 32 32" fill="none" className={className} aria-hidden="true">
      <path
        d="M16 2.5 27 6.5v8.2c0 8-4.6 13.4-11 14.8-6.4-1.4-11-6.8-11-14.8V6.5L16 2.5Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path d="M16 9v9" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      <circle cx="16" cy="21" r="1.1" fill="currentColor" />
    </svg>
  );
}

/**
 * Empty-state illustration: a calm watch-tower scanning a quiet horizon.
 * Used in place of a bare lucide ShieldCheck icon for "no threats" states.
 */
export function AllClearIllustration({ className }: GuardMarkProps) {
  return (
    <svg viewBox="0 0 160 110" fill="none" className={className} aria-hidden="true">
      <line x1="8" y1="88" x2="152" y2="88" stroke="currentColor" strokeOpacity="0.25" strokeWidth="1.5" />
      <path
        d="M80 14 108 24v22c0 21-12 34.5-28 38-16-3.5-28-17-28-38V24L80 14Z"
        fill="currentColor"
        fillOpacity="0.08"
        stroke="currentColor"
        strokeOpacity="0.55"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="M80 33v22" stroke="currentColor" strokeOpacity="0.7" strokeWidth="2" strokeLinecap="round" />
      <circle cx="80" cy="63" r="1.3" fill="currentColor" fillOpacity="0.7" />
      <g strokeOpacity="0.35" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round">
        <path d="M118 44c6 4 9 10 9 18" />
        <path d="M132 38c9 6 14 16 14 27" />
      </g>
      <circle cx="42" cy="76" r="2" fill="currentColor" fillOpacity="0.3" />
      <circle cx="120" cy="80" r="1.4" fill="currentColor" fillOpacity="0.3" />
    </svg>
  );
}
