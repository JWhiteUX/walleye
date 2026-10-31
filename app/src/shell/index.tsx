// Placeholder layout. Owner: Agent D. Replace with the real shell (keep the
// AppShell export). The shell composes every panel by its public export:
//   TimelinePanel, QueuePanel (Agent E) · CasePanel (Agent F)
//   SessionTable, PacketPane (Agent D)
import { CasePanel } from "../case";
import { PacketPane } from "../packets";
import { QueuePanel } from "../queue";
import { SessionTable } from "../table";
import { TimelinePanel } from "../timeline";

export function AppShell() {
  return (
    <div
      style={{
        display: "grid",
        height: "100%",
        gridTemplateColumns: "1fr 360px",
        gridTemplateRows: "auto 220px 1fr 1fr",
      }}
    >
      <header style={{ gridColumn: "1 / -1", padding: 8, borderBottom: "1px solid var(--wl-border)" }}>
        <h1 style={{ fontSize: 15, margin: 0 }}>Walleye</h1>
      </header>
      <main style={{ display: "contents" }}>
        <TimelinePanel />
        <QueuePanel />
        <SessionTable />
        <CasePanel />
        <PacketPane />
      </main>
    </div>
  );
}
