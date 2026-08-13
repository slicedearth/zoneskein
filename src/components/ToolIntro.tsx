interface ToolIntroProps {
  readonly children: React.ReactNode;
  readonly eyebrow: string;
  readonly title: string;
}

export function ToolIntro({ children, eyebrow, title }: ToolIntroProps) {
  return (
    <header className="tool-intro">
      <p className="eyebrow">{eyebrow}</p>
      <h1>{title}</h1>
      <p className="lede">{children}</p>
    </header>
  );
}
