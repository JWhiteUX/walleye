import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../shared/ipc";
import { resetCaptureKinds } from "../shared/captureKind";
import { resetMock } from "../shared/mock";
import { useSelection } from "../shared/selection";
import { useSession } from "../shared/session";
import { DEVICE_FRAMES_CAP } from "../shared/wifi";
import { fetchSource, frameSource, sourceKey, sourceTitle } from "./source";
import { PacketPane } from ".";

const R = { start: 10, end: 20 };

describe("frameSource", () => {
  it("prefers the selected flow, then the focused device, else nothing", () => {
    expect(frameSource({ flow_ids: [7, 9], device: "02:5e:00:53:e7:01", time_range: R })).toEqual({ kind: "flow", flowId: 7 });
    expect(frameSource({ flow_ids: [], device: "02:5e:00:53:e7:01", time_range: R })).toEqual({
      kind: "device",
      mac: "02:5e:00:53:e7:01",
      timeRange: R,
    });
    expect(frameSource({ flow_ids: [], device: null, time_range: R })).toEqual({ kind: "none" });
  });

  it("keys device sources by MAC and time range", () => {
    const a = sourceKey({ kind: "device", mac: "00:00:5e:00:53:01", timeRange: null });
    const b = sourceKey({ kind: "device", mac: "00:00:5e:00:53:01", timeRange: R });
    expect(a).not.toBe(b);
    expect(sourceKey({ kind: "flow", flowId: 3 })).toBe("flow:3");
    expect(sourceKey({ kind: "none" })).toBeNull();
  });

  it("calls flowFrames or deviceFrames", async () => {
    const fake = { flowFrames: vi.fn(async () => []), deviceFrames: vi.fn(async () => []) };
    await fetchSource({ kind: "flow", flowId: 3 }, fake);
    await fetchSource({ kind: "device", mac: "00:00:5e:00:53:01", timeRange: R }, fake);
    expect(fake.flowFrames).toHaveBeenCalledWith(3);
    expect(fake.deviceFrames).toHaveBeenCalledWith("00:00:5e:00:53:01", R);
  });

  it("titles say whose frames they are", () => {
    expect(sourceTitle({ kind: "flow", flowId: 27 }, 56)).toBe("Frames of flow 27 (56)");
    expect(sourceTitle({ kind: "device", mac: "d6:5e:00:53:de:ad", timeRange: null }, 449)).toBe("Frames of device d6:5e:00:53:de:ad (rand) (449)");
    expect(sourceTitle({ kind: "device", mac: "00:00:5e:00:53:01", timeRange: R }, null)).toBe("Frames of device 00:00:5e:00:53:01 in time range");
    expect(sourceTitle({ kind: "device", mac: "00:00:5e:00:53:01", timeRange: null }, DEVICE_FRAMES_CAP)).toMatch(/first 10,000\)$/);
    // flow_frames is uncapped: no "first N" note however many frames.
    expect(sourceTitle({ kind: "flow", flowId: 1 }, 25_000)).toBe("Frames of flow 1 (25,000)");
  });
});

describe("PacketPane on an 802.11 capture", () => {
  beforeEach(async () => {
    resetMock({ open: true, dataset: "wifi" });
    resetCaptureKinds();
    useSelection.getState().reset();
    useSession.getState().setSession(await api.currentCapture());
  });
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    useSession.getState().setSession(null);
  });

  it("explains how to list frames when nothing is focused", () => {
    render(<PacketPane />);
    expect(screen.getByText(/Select an access point, client or Wi-Fi frame/)).toBeInTheDocument();
  });

  it("uses the Wi-Fi empty state for a mixed capture whose first interface is Ethernet", async () => {
    const s = useSession.getState().session!;
    act(() => useSession.getState().setSession({ ...s, capture: { ...s.capture, capture_id: "mixed-0002", link_type: 1 } }));
    render(<PacketPane />);
    await waitFor(() => expect(screen.getByText(/Select an access point, client or Wi-Fi frame/)).toBeInTheDocument());
  });

  it("keeps the session empty state on a wired capture", async () => {
    resetMock({ open: true });
    act(() => useSession.getState().setSession(null));
    const s = await api.currentCapture();
    act(() => useSession.getState().setSession(s));
    render(<PacketPane />);
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.getByText("Select a session to list its frames.")).toBeInTheDocument();
  });

  it("lists the focused device's frames within the time range, and a selected flow wins", async () => {
    const dev = vi.spyOn(api, "deviceFrames");
    const flow = vi.spyOn(api, "flowFrames").mockResolvedValue([]);
    render(<PacketPane />);
    act(() => useSelection.getState().selectDevice("d6:5e:00:53:de:ad"));
    await waitFor(() => expect(screen.getByTestId("frame-source")).toHaveTextContent(/^Frames of device d6:5e:00:53:de:ad \(rand\) \(\d+\)$/));
    expect(dev).toHaveBeenLastCalledWith("d6:5e:00:53:de:ad", null);
    expect(screen.getByRole("listbox", { name: /Frames of device d6:5e:00:53:de:ad/ })).toBeInTheDocument();

    act(() => useSelection.getState().setTimeRange(R));
    await waitFor(() => expect(dev).toHaveBeenLastCalledWith("d6:5e:00:53:de:ad", R));
    await waitFor(() => expect(screen.getByText("No frames of this device in the selected time range.")).toBeInTheDocument());

    act(() => useSelection.getState().selectFlows([5]));
    await waitFor(() => expect(flow).toHaveBeenCalledWith(5));
    expect(screen.getByTestId("frame-source")).toHaveTextContent("Frames of flow 5");
  });
});
