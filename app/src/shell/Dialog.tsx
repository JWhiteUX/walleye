// Minimal modal dialog: traps Tab, closes on Escape, restores focus on unmount.
import { useEffect, useRef, type ReactNode } from "react";

const FOCUSABLE = 'button:not([disabled]), input:not([disabled]), select, textarea, [href], [tabindex]:not([tabindex="-1"])';

export function Dialog({
  labelledBy,
  describedBy,
  role = "dialog",
  onClose,
  className,
  children,
  testId,
}: {
  labelledBy: string;
  describedBy?: string;
  role?: "dialog" | "alertdialog";
  onClose: () => void;
  className?: string;
  children: ReactNode;
  testId?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  });

  // Escape closes the top-most dialog even if focus drifted outside it.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      const dialogs = document.querySelectorAll('[aria-modal="true"]');
      if (dialogs[dialogs.length - 1] !== ref.current) return;
      e.preventDefault();
      onCloseRef.current();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current;
    const first = el?.querySelector<HTMLElement>("[data-autofocus]") ?? el?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? el)?.focus();
    return () => {
      if (prev && document.contains(prev)) prev.focus();
    };
  }, []);

  return (
    <div className="wl-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onCloseRef.current()}>
      <div
        ref={ref}
        role={role}
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        tabIndex={-1}
        className={`wl-dialog ${className ?? ""}`}
        data-testid={testId}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            e.stopPropagation();
            onCloseRef.current();
            return;
          }
          if (e.key !== "Tab") return;
          const items = [...(ref.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? [])];
          if (!items.length) return;
          const first = items[0]!;
          const last = items[items.length - 1]!;
          if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }}
      >
        {children}
      </div>
    </div>
  );
}
