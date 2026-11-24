/** Envelope download: never strip inner dots. test.test.jpg → test.test.jpg.sg1 */
export function envelopeFileName(original: string): string {
  const base = (original || "file").replace(/\.(sg1|sgwk|sga)$/i, "");
  return `${base}.sg1`;
}

/** Recovered original: keep every dot. Only peel a Sigil suffix. */
export function recoveredFileName(headerName: string | undefined, fallback: string): string {
  const fromHeader = (headerName || "").replace(/\0/g, "").trim();
  if (fromHeader) return fromHeader;
  const f = (fallback || "recovered.bin").replace(/\.(sg1|sgwk|sga)$/i, "");
  return f || "recovered.bin";
}
