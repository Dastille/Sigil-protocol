function asSource(data: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(data.length);
  copy.set(data);
  return copy;
}

async function through(
  data: Uint8Array,
  stream: CompressionStream | DecompressionStream,
): Promise<Uint8Array> {
  const input = asSource(data);
  const blob = new Blob([input]);
  const piped = blob.stream().pipeThrough(stream);
  const buf = await new Response(piped).arrayBuffer();
  return new Uint8Array(buf);
}

export async function deflate(data: Uint8Array): Promise<Uint8Array> {
  if (data.length === 0) return data;
  return through(data, new CompressionStream("deflate-raw"));
}

export async function inflate(data: Uint8Array): Promise<Uint8Array> {
  if (data.length === 0) return data;
  return through(data, new DecompressionStream("deflate-raw"));
}

/** Compress only when DEFLATE actually shrinks the payload. */
export async function maybeDeflate(
  data: Uint8Array,
): Promise<{ bytes: Uint8Array; compressed: boolean }> {
  if (data.length < 24) return { bytes: data, compressed: false };
  const z = await deflate(data);
  if (z.length < data.length) return { bytes: z, compressed: true };
  return { bytes: data, compressed: false };
}
