// Packet pane (Agent D): frames of the selected flow, the decode tree and a
// hex view of the selected frame, with tree <-> byte highlighting both ways.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FrameRef } from "../shared/bindings/FrameRef";
import type { PacketView } from "../shared/bindings/PacketView";
import { pinEvidence } from "../shared/caseEvents";
import { useRegisterCommands, type Command } from "../shared/commands";
import { formatTs } from "../shared/format";
import { WalleyeError, api } from "../shared/ipc";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { DecodeTree } from "./DecodeTree";
import { FrameList } from "./FrameList";
import { ancestorIds, deepestNodeAt, effectiveRange, flattenTree, hex2, parseHex, truncationNote, type NodeId } from "./hex";
import { HexView } from "./HexView";
import "./packets.css";

type Load<T> = { status: "idle" } | { status: "loading" } | { status: "ok"; data: T } | { status: "error"; error: WalleyeError };

const IDLE = { status: "idle" } as const;
const LOADING = { status: "loading" } as const;

function useLoad<T>(key: number | null, enabled: boolean, fetch: (k: number) => Promise<T>): Load<T> {
  const [state, setState] = useState<{ key: number | null; load: Load<T> }>({ key: null, load: { status: "idle" } });
  useEffect(() => {
    if (key === null || !enabled) return;
    let live = true;
    fetch(key).then(
      (data) => live && setState({ key, load: { status: "ok", data } }),
      (e) =>
        live &&
        setState({
          key,
          load: { status: "error", error: e instanceof WalleyeError ? e : new WalleyeError({ code: "internal", message: String(e), span: null }) },
        }),
    );
    return () => {
      live = false;
    };
  }, [key, enabled, fetch]);
  if (key === null || !enabled) return IDLE;
  return state.key === key ? state.load : LOADING;
}

export function PacketPane() {
  const session = useSession((s) => s.session);
  const flowId = useSelection((s) => s.flow_ids[0] ?? null);
  const frameNo = useSelection((s) => s.frame_no);
  const selectFrame = useSelection((s) => s.selectFrame);
  const [status, setStatus] = useState("");

  const frames = useLoad<FrameRef[]>(flowId, !!session, api.flowFrames);
  const packet = useLoad<PacketView>(frameNo, !!session, api.packet);

  const frameList = useMemo(() => (frames.status === "ok" ? frames.data : []), [frames]);
  const view = packet.status === "ok" ? packet.data : null;
  const bytes = useMemo(() => (view ? parseHex(view.bytes_hex) : new Uint8Array()), [view]);
  const flat = useMemo(() => (view ? flattenTree(view.decode_tree, bytes.length) : []), [view, bytes]);
  const byId = useMemo(() => new Map(flat.map((f) => [f.id, f])), [flat]);

  const [selNode, setSelNode] = useState<{ frame: number | null; id: NodeId | null }>({ frame: null, id: null });
  const [expanded, setExpanded] = useState<{ frame: number | null; ids: Set<NodeId> }>({ frame: null, ids: new Set() });
  const [cursor, setCursor] = useState<{ frame: number | null; off: number | null }>({ frame: null, off: null });
  const nodeId = selNode.frame === frameNo ? selNode.id : null;
  const openIds = useMemo(() => (expanded.frame === frameNo ? expanded.ids : new Set<NodeId>()), [expanded, frameNo]);
  const cursorOff = cursor.frame === frameNo ? cursor.off : null;

  const highlight = useMemo(() => effectiveRange(byId, nodeId), [byId, nodeId]);

  const selectNode = useCallback(
    (id: NodeId) => {
      setSelNode({ frame: frameNo, id });
      const r = effectiveRange(byId, id);
      setCursor({ frame: frameNo, off: r ? r.start : null });
    },
    [byId, frameNo],
  );
  const toggle = useCallback(
    (id: NodeId, open?: boolean) =>
      setExpanded((e) => {
        const ids = new Set(e.frame === frameNo ? e.ids : []);
        const want = open ?? !ids.has(id);
        if (want) ids.add(id);
        else ids.delete(id);
        return { frame: frameNo, ids };
      }),
    [frameNo],
  );
  const pickByte = useCallback(
    (off: number) => {
      setCursor({ frame: frameNo, off });
      const hit = deepestNodeAt(flat, off);
      if (!hit) return;
      setSelNode({ frame: frameNo, id: hit.id });
      setExpanded((e) => {
        const ids = new Set(e.frame === frameNo ? e.ids : []);
        ancestorIds(hit.id).forEach((a) => ids.add(a));
        return { frame: frameNo, ids };
      });
    },
    [flat, frameNo],
  );

  const readout = useMemo(() => {
    if (!view) return "";
    const parts: string[] = [];
    if (cursorOff !== null && cursorOff < bytes.length) parts.push(`Byte 0x${cursorOff.toString(16).padStart(4, "0")} = 0x${hex2(bytes[cursorOff]!)}`);
    const node = nodeId ? byId.get(nodeId) : null;
    if (node) parts.push(node.node.label);
    if (highlight) parts.push(`${highlight.len} byte${highlight.len === 1 ? "" : "s"} at offset ${highlight.start}`);
    return parts.join(" · ") || "Select a tree node or a byte.";
  }, [view, cursorOff, bytes, nodeId, byId, highlight]);

  // Commands are registered once; they read the current frames/tree through this ref.
  const live = useRef({ frameList, flat, frameNo });
  useEffect(() => {
    live.current = { frameList, flat, frameNo };
  });

  const step = useCallback((d: number) => {
    const list = live.current.frameList;
    if (!list.length) return;
    const i = list.findIndex((f) => f.frame_no === useSelection.getState().frame_no);
    const n = list[Math.max(0, Math.min(list.length - 1, i < 0 ? 0 : i + d))];
    if (n) useSelection.getState().selectFrame(n.frame_no);
  }, []);

  const pinFrame = useCallback(async () => {
    const f = useSelection.getState().frame_no;
    if (f === null) return;
    try {
      await pinEvidence({ kind: "frame", frame_no: f });
      setStatus(`Pinned frame ${f} to the case.`);
    } catch (e) {
      setStatus(`Could not pin frame ${f}: ${(e as Error).message}`);
    }
  }, []);

  const expandAll = useCallback((open: boolean) => {
    const { flat: nodes, frameNo: frame } = live.current;
    setExpanded({ frame, ids: open ? new Set(nodes.filter((f) => f.node.children.length).map((f) => f.id)) : new Set() });
  }, []);

  const commands = useMemo<Command[]>(
    () => [
      { id: "packets.next-frame", title: "Next frame in flow", group: "Packets", shortcut: "]", run: () => step(1) },
      { id: "packets.prev-frame", title: "Previous frame in flow", group: "Packets", shortcut: "[", run: () => step(-1) },
      {
        id: "packets.pin-frame",
        title: "Pin selected frame to case",
        group: "Packets",
        shortcut: "shift+f",
        run: () => void pinFrame(),
        enabled: () => useSelection.getState().frame_no !== null && !!useSession.getState().session,
      },
      { id: "packets.expand-all", title: "Expand all decode layers", group: "Packets", shortcut: "z o", run: () => expandAll(true) },
      { id: "packets.collapse-all", title: "Collapse all decode layers", group: "Packets", shortcut: "z c", run: () => expandAll(false) },
    ],
    [step, pinFrame, expandAll],
  );
  useRegisterCommands(commands);

  const note = view ? truncationNote(view.caplen, view.wirelen, bytes.length) : null;

  return (
    <section aria-label="Packets" data-testid="packets-panel" className="wl-packets">
      <div className="wl-packets-bar">
        <h2 className="wl-panel-title">Packets</h2>
        {view && (
          <span className="wl-packets-meta" data-testid="packet-meta">
            Frame <strong className="wl-mono">{view.frame_no}</strong> · {view.caplen} of {view.wirelen} bytes ·{" "}
            <span className="wl-mono">{formatTs(view.ts)}</span>
          </span>
        )}
        <span className="wl-spacer" />
        <button type="button" onClick={() => step(-1)} disabled={!frameList.length} title="Previous frame ([)">
          Prev
        </button>
        <button type="button" onClick={() => step(1)} disabled={!frameList.length} title="Next frame (])">
          Next
        </button>
        <button type="button" onClick={() => void pinFrame()} disabled={frameNo === null || !session} title="Pin frame (Shift+F)">
          Pin frame
        </button>
        <span role="status" className="wl-packets-msg">
          {status}
        </span>
      </div>
      {!session ? (
        <p className="wl-empty">No capture open.</p>
      ) : (
        <div className="wl-packets-body">
          <div className="wl-packets-col wl-packets-frames">
            {flowId === null ? (
              <p className="wl-empty">Select a session to list its frames.</p>
            ) : frames.status === "error" ? (
              <p className="wl-empty wl-error-text" role="alert">
                ⚠ Could not list frames of flow {flowId}: {frames.error.message}
              </p>
            ) : frames.status === "loading" ? (
              <p className="wl-empty">Loading frames…</p>
            ) : (
              <FrameList frames={frameList} selected={frameNo} onSelect={selectFrame} />
            )}
          </div>
          <div className="wl-packets-col wl-packets-tree">
            {frameNo === null ? (
              <p className="wl-empty">Select a frame to decode it.</p>
            ) : packet.status === "error" ? (
              <p className="wl-empty wl-error-text" role="alert" data-testid="packet-error">
                ⚠{" "}
                {packet.error.code === "not_found"
                  ? `No bytes available for frame ${frameNo}.`
                  : `Could not decode frame ${frameNo}.`}{" "}
                <span className="wl-text-muted">({packet.error.code}: {packet.error.message})</span>
              </p>
            ) : packet.status !== "ok" ? (
              <p className="wl-empty">Decoding…</p>
            ) : (
              <>
                {note && (
                  <p className="wl-warn-text" role="note" data-testid="truncation-note">
                    ⚠ {note}
                  </p>
                )}
                <DecodeTree flat={flat} expanded={openIds} selected={nodeId} onSelect={selectNode} onToggle={toggle} />
              </>
            )}
          </div>
          <div className="wl-packets-col wl-packets-hex">
            {view && packet.status === "ok" && (
              <HexView bytes={bytes} highlight={highlight} cursor={cursorOff} onPick={pickByte} readout={readout} />
            )}
          </div>
        </div>
      )}
    </section>
  );
}
