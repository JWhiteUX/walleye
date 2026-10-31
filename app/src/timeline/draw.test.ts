import { describe, expect, it } from "vitest";
import type { Shape } from "../shared/encoding";
import { EVENT_ENCODING } from "../shared/encoding";
import { type PathSink, shapePath, STROKED } from "./draw";
import { KINDS } from "./layout";

function recorder() {
  const ops: string[] = [];
  const sink: PathSink = {
    moveTo: () => ops.push("M"),
    lineTo: () => ops.push("L"),
    arc: () => ops.push("A"),
    rect: () => ops.push("R"),
    closePath: () => ops.push("Z"),
  };
  return { ops, sink };
}

describe("shapePath", () => {
  const sig = (shape: Shape) => {
    const r = recorder();
    shapePath(r.sink, shape, 10, 10, 3);
    return r.ops.join("");
  };
  it("draws a distinct geometry for each event kind", () => {
    const sigs = KINDS.map((k) => sig(EVENT_ENCODING[k].shape));
    expect(sigs).toEqual(["MA", "R", "MLLZ", "MLLLZ", "MLML"]);
    expect(new Set(sigs).size).toBe(KINDS.length);
  });
  it("only the cross is stroked (it has no area)", () => {
    expect([...STROKED]).toEqual(["cross"]);
  });
});
