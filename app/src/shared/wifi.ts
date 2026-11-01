// 802.11 display helpers shared by the table, packet pane, timeline and queue
// (CONTRACTS §11). Pure.
import type { CaptureRow } from "./bindings/CaptureRow";

/** LINKTYPE_IEEE802_11 (105) and LINKTYPE_IEEE802_11_RADIOTAP (127). */
export const isWifiLinkType = (lt: number | null | undefined): boolean => lt === 105 || lt === 127;
export const isWifiCapture = (c: Pick<CaptureRow, "link_type"> | null | undefined): boolean => !!c && isWifiLinkType(c.link_type);

const MAC = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i;
export const isMac = (s: string): boolean => MAC.test(s);

/**
 * Locally administered bit (0x02 of the first octet): privacy-randomized
 * clients, virtual APs or spoofed addresses.
 */
export function isRandomizedMac(mac: string): boolean {
  if (!isMac(mac)) return false;
  const b = parseInt(mac.slice(0, 2), 16);
  // Group (multicast/broadcast) addresses also have the bit set; they are not devices.
  return (b & 0x01) === 0 && (b & 0x02) !== 0;
}

export const BROADCAST_MAC = "ff:ff:ff:ff:ff:ff";

/** Short text marker appended to randomized MACs. Text, so it never relies on colour. */
export const RANDOMIZED_MARK = "(rand)";
export const RANDOMIZED_HELP = "Randomized: locally administered address (privacy-randomized client, virtual AP or spoofed)";

/** "02:00:5e:00:53:01 (rand)" for randomized addresses, "… (broadcast)", else the bare MAC. */
export function macLabel(mac: string): string {
  if (mac.toLowerCase() === BROADCAST_MAC) return `${mac} (broadcast)`;
  return isRandomizedMac(mac) ? `${mac} ${RANDOMIZED_MARK}` : mac;
}

/** For screen readers and tooltips: "02:00:5e:00:53:01, randomized". */
export function macSpoken(mac: string): string {
  return isRandomizedMac(mac) ? `${mac}, randomized` : mac;
}

/**
 * How an SSID cell reads: "" means hidden (beacon) or wildcard (probe
 * request), null means the frame kind carries no SSID. The caller renders the
 * placeholder differently (italic) so a network literally named "(hidden)"
 * can't pass for one.
 */
export function ssidText(ssid: string | null | undefined, kind?: string): { text: string; placeholder: boolean } {
  if (ssid === null || ssid === undefined) return { text: kind === undefined ? "(hidden)" : "", placeholder: kind === undefined };
  if (ssid === "") return { text: kind === "probe_req" ? "(wildcard)" : "(hidden)", placeholder: true };
  return { text: ssid, placeholder: false };
}

/**
 * An SSID in double quotes for display inside other text, with `\` and `"`
 * backslash-escaped so a quote inside the name can't close it early and forge
 * what follows. Pass it through `visible()` first (or after: escapes are ASCII).
 */
export function quoteSsid(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

const KIND_LABEL: Record<string, string> = {
  beacon: "Beacon",
  probe_req: "Probe request",
  probe_resp: "Probe response",
  auth: "Auth",
  deauth: "Deauth",
  assoc_req: "Assoc request",
  assoc_resp: "Assoc response",
  reassoc_req: "Reassoc request",
  reassoc_resp: "Reassoc response",
  disassoc: "Disassoc",
  action: "Action",
  mgmt_other: "Management",
  data: "Data",
  null: "Null",
  eapol: "EAPOL",
};
export const wifiKindLabel = (k: string): string => KIND_LABEL[k] ?? k;
