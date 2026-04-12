interface Props {
  lines: string[];
}

export function LogPanel({ lines }: Props) {
  return (
    <div className="panel log">
      <h2>
        Log
        <span className="badge-inline">{lines.length}</span>
      </h2>
      <div className="log-panel">{lines.length === 0 ? "—" : lines.join("\n")}</div>
    </div>
  );
}
