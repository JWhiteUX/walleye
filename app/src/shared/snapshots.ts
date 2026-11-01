// The timeline (Agent E) registers a function that returns a PNG snapshot of
// its canvas; report export (Agent F) asks for it. Base64 without the
// "data:image/png;base64," prefix, or null when nothing is drawn.
type Provider = () => string | null;
let provider: Provider | null = null;

export function registerTimelineSnapshot(p: Provider): () => void {
  provider = p;
  return () => {
    if (provider === p) provider = null;
  };
}

export function getTimelineSnapshot(): string | null {
  return provider ? provider() : null;
}
