import { cleanup, fireEvent, render } from "@testing-library/react";
import { useMemo } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useRegisterCommands, type Command } from "../shared/commands";
import { useGlobalKeys } from "./useGlobalKeys";

function Harness({ cmds }: { cmds: Command[] }) {
  const stable = useMemo(() => cmds, [cmds]);
  useRegisterCommands(stable);
  useGlobalKeys();
  return <input aria-label="text" />;
}

afterEach(cleanup);

const key = (k: string, o: Partial<KeyboardEventInit> = {}) => fireEvent.keyDown(window, { key: k, ...o });

describe("global key handler", () => {
  it("runs commands by chord and by sequence, and skips disabled ones", () => {
    const palette = vi.fn();
    const goTimeline = vi.fn();
    const pin = vi.fn();
    const cmds: Command[] = [
      { id: "a.palette", title: "Palette", group: "G", shortcut: "ctrl+k", run: palette },
      { id: "a.go", title: "Go", group: "G", shortcut: "g t", run: goTimeline },
      { id: "a.pin", title: "Pin", group: "G", shortcut: "shift+p", run: pin, enabled: () => false },
    ];
    render(<Harness cmds={cmds} />);
    key("k", { ctrlKey: true });
    expect(palette).toHaveBeenCalledTimes(1);
    key("g");
    expect(goTimeline).not.toHaveBeenCalled();
    key("t");
    expect(goTimeline).toHaveBeenCalledTimes(1);
    key("P", { shiftKey: true });
    expect(pin).not.toHaveBeenCalled();
  });

  it("ignores plain keys typed into text fields and events already handled", () => {
    const go = vi.fn();
    const slash = vi.fn();
    const { getByLabelText } = render(
      <Harness
        cmds={[
          { id: "b.go", title: "Go", group: "G", shortcut: "g t", run: go },
          { id: "b.slash", title: "Slash", group: "G", shortcut: "/", run: slash },
        ]}
      />,
    );
    const input = getByLabelText("text");
    input.focus();
    fireEvent.keyDown(input, { key: "g" });
    fireEvent.keyDown(input, { key: "t" });
    fireEvent.keyDown(input, { key: "/" });
    expect(go).not.toHaveBeenCalled();
    expect(slash).not.toHaveBeenCalled();
    input.blur();
    const ev = new KeyboardEvent("keydown", { key: "/", cancelable: true });
    ev.preventDefault();
    window.dispatchEvent(ev);
    expect(slash).not.toHaveBeenCalled();
    key("/");
    expect(slash).toHaveBeenCalledTimes(1);
  });

  it("unregisters commands on unmount", () => {
    const run = vi.fn();
    const { unmount } = render(<Harness cmds={[{ id: "c.x", title: "X", group: "G", shortcut: "ctrl+j", run }]} />);
    unmount();
    key("j", { ctrlKey: true });
    expect(run).not.toHaveBeenCalled();
  });
});
