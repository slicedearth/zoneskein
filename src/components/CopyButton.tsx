import { useEffect, useRef, useState } from 'react';

interface CopyButtonProps {
  readonly disabled?: boolean;
  readonly label?: string;
  readonly text: string;
}

interface CopyFeedback {
  readonly state: 'copied' | 'failed';
  readonly text: string;
}

export function CopyButton({ disabled = false, label = 'Copy', text }: CopyButtonProps) {
  const [feedback, setFeedback] = useState<CopyFeedback | null>(null);
  const timeout = useRef<number | undefined>(undefined);

  useEffect(
    () => () => {
      window.clearTimeout(timeout.current);
    },
    [],
  );

  async function copy() {
    if (disabled) return;
    const copiedText = text;
    try {
      await navigator.clipboard.writeText(copiedText);
      setFeedback({ state: 'copied', text: copiedText });
    } catch {
      setFeedback({ state: 'failed', text: copiedText });
    }
    window.clearTimeout(timeout.current);
    timeout.current = window.setTimeout(
      () => setFeedback((current) => (current?.text === copiedText ? null : current)),
      1800,
    );
  }

  const state = disabled || feedback?.text !== text ? 'idle' : feedback.state;
  const visible = state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label;
  return (
    <span>
      <button
        className="quiet-button"
        type="button"
        disabled={disabled}
        onClick={() => void copy()}
      >
        {visible}
      </button>
      <span className="visually-hidden" role="status" aria-live="polite">
        {state === 'copied'
          ? `${label} succeeded.`
          : state === 'failed'
            ? `${label} failed.`
            : ''}
      </span>
    </span>
  );
}
