import { useEffect, useRef, useState } from 'react';

interface CopyButtonProps {
  readonly label?: string;
  readonly text: string;
}

export function CopyButton({ label = 'Copy', text }: CopyButtonProps) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timeout = useRef<number | undefined>(undefined);

  useEffect(
    () => () => {
      window.clearTimeout(timeout.current);
    },
    [],
  );

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState('copied');
    } catch {
      setState('failed');
    }
    window.clearTimeout(timeout.current);
    timeout.current = window.setTimeout(() => setState('idle'), 1800);
  }

  const visible = state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label;
  return (
    <button className="quiet-button" type="button" onClick={() => void copy()}>
      {visible}
    </button>
  );
}
