import { beforeEach, describe, expect, it } from "vitest";
import { selectionScope, useSelection } from "./selection";

describe("selection store", () => {
  beforeEach(() => useSelection.getState().reset());

  it("applies evidence to flows and first frame", () => {
    useSelection.getState().applyEvidence({ flow_ids: [3, 3, 9], frame_nos: [41, 50], truncated: false, total: 2 });
    const s = useSelection.getState();
    expect(s.flow_ids).toEqual([3, 9]);
    expect(s.frame_no).toBe(41);
  });

  it("drops empty time ranges", () => {
    useSelection.getState().setTimeRange({ start: 10, end: 10 });
    expect(useSelection.getState().time_range).toBeNull();
  });

  it("clearSelection keeps the filter", () => {
    const st = useSelection.getState();
    st.setFilter("host 10.0.0.5");
    st.toggleHost("10.0.0.5");
    st.clearSelection();
    expect(selectionScope(useSelection.getState())).toEqual({ filter: "host 10.0.0.5", time_range: null, hosts: [], flow_ids: [] });
  });
});
