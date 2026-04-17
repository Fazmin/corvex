import { useEffect } from "react";

export type ToastKind = "success" | "error" | "info";

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

interface Props {
  toasts: Toast[];
  onDismiss: (id: number) => void;
  autoDismissMs?: number;
}

export function ToastContainer({ toasts, onDismiss, autoDismissMs = 4500 }: Props) {
  return (
    <div className="toast-stack" aria-live="polite">
      {toasts.map((t) => (
        <ToastItem key={t.id} toast={t} onDismiss={onDismiss} autoDismissMs={autoDismissMs} />
      ))}
    </div>
  );
}

function ToastItem({
  toast,
  onDismiss,
  autoDismissMs,
}: {
  toast: Toast;
  onDismiss: (id: number) => void;
  autoDismissMs: number;
}) {
  useEffect(() => {
    const timer = window.setTimeout(() => onDismiss(toast.id), autoDismissMs);
    return () => window.clearTimeout(timer);
  }, [toast.id, onDismiss, autoDismissMs]);

  return (
    <div className={`toast toast-${toast.kind}`} role="status">
      <span className="toast-message">{toast.message}</span>
      <button
        type="button"
        className="toast-dismiss"
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss"
      >
        ×
      </button>
    </div>
  );
}
