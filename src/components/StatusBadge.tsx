export type StatusTone = 'pass' | 'information' | 'warning' | 'error' | 'unknown';

interface StatusBadgeProps {
  readonly children: React.ReactNode;
  readonly tone: StatusTone;
}

const ICONS: Readonly<Record<StatusTone, string>> = {
  error: '×',
  information: 'i',
  pass: '✓',
  unknown: '?',
  warning: '!',
};

export function StatusBadge({ children, tone }: StatusBadgeProps) {
  return (
    <span className={`status-badge status-${tone}`}>
      <span aria-hidden="true">{ICONS[tone]}</span>
      {children}
    </span>
  );
}
