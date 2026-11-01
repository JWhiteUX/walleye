// Shell entry (Agent D). Composes every panel by its public export:
//   TimelinePanel, QueuePanel (Agent E) · CasePanel (Agent F)
//   SessionTable, PacketPane (Agent D)
// `?bench=table` renders the 1M-row table benchmark instead. Only in dev
// builds, or a production build made with VITE_WALLEYE_BENCH=1 (to measure
// React's production mode); release builds drop the benchmark entirely.
import { lazy, Suspense } from "react";
import { AppShell as Shell } from "./AppShell";

const TableBench =
  import.meta.env.DEV || import.meta.env.VITE_WALLEYE_BENCH === "1"
    ? lazy(() => import("../table/TableBench").then((m) => ({ default: m.TableBench })))
    : null;

export function AppShell() {
  if (TableBench && typeof window !== "undefined" && new URLSearchParams(window.location.search).get("bench") === "table") {
    return (
      <Suspense fallback={<p>Loading benchmark…</p>}>
        <TableBench />
      </Suspense>
    );
  }
  return <Shell />;
}
