import { create } from "zustand";
import type { GraphMember, WorkSpec } from "./graph";
import { MAX_STARS } from "./graph";
import type { SealResult } from "./types";

export interface SkyChart {
  id: string;
  name: string;
  memberDigests: string[];
  work: WorkSpec | null;
}

interface SkyState {
  stars: Record<string, GraphMember>;
  charts: SkyChart[];
  activeId: string | null;
  packed: SealResult | null;
  addStar: (m: Omit<GraphMember, "id"> | GraphMember) => string;
  addStarToActive: (m: Omit<GraphMember, "id"> | GraphMember) => { digest: string; chartName: string; count: number; already: boolean };
  addTo: (chartId: string, digest: string) => void;
  removeFrom: (chartId: string, digest: string) => void;
  createChart: (name: string, work?: WorkSpec | null) => SkyChart;
  setActive: (id: string) => void;
  renameActive: (name: string) => void;
  setWork: (chartId: string, work: WorkSpec | null) => void;
  setPacked: (g: SealResult | null) => void;
  ingestChart: (title: string, members: GraphMember[], work: WorkSpec | null) => void;
  hydrateActive: (members: GraphMember[], work?: WorkSpec | null) => void;
  clearActive: () => void;
}

function nid(): string {
  return Math.random().toString(36).slice(2, 10);
}

function asStar(m: Omit<GraphMember, "id"> | GraphMember): GraphMember {
  return {
    ...m,
    id: m.digestHex,
    index: "index" in m && typeof m.index === "number" ? m.index : 0,
    total: "total" in m && typeof m.total === "number" ? m.total : 1,
  };
}

export function selectActiveChart(s: SkyState): SkyChart | null {
  return s.charts.find((c) => c.id === s.activeId) ?? s.charts[0] ?? null;
}

export function selectActiveMembers(s: SkyState): GraphMember[] {
  const c = selectActiveChart(s);
  if (!c) return [];
  return c.memberDigests.map((d) => s.stars[d]).filter((x): x is GraphMember => Boolean(x));
}

export function chartsForStar(s: SkyState, digest: string): SkyChart[] {
  return s.charts.filter((c) => c.memberDigests.includes(digest));
}

export const useConstellation = create<SkyState>((set, get) => ({
  stars: {},
  charts: [],
  activeId: null,
  packed: null,

  addStar: (m) => {
    const star = asStar(m);
    const stars = { ...get().stars, [star.digestHex]: star };
    set({ stars });
    return star.digestHex;
  },

  addStarToActive: (m) => {
    const star = asStar(m);
    const stars = { ...get().stars, [star.digestHex]: star };
    let { charts, activeId } = get();
    if (!activeId || !charts.some((c) => c.id === activeId)) {
      const c: SkyChart = { id: nid(), name: "First sky", memberDigests: [], work: null };
      charts = [...charts, c];
      activeId = c.id;
    }
    const chartsNext = charts.map((c) => {
      if (c.id !== activeId) return c;
      if (c.memberDigests.includes(star.digestHex)) return c;
      if (c.memberDigests.length >= MAX_STARS) return c;
      return { ...c, memberDigests: [...c.memberDigests, star.digestHex] };
    });
    const chart = chartsNext.find((c) => c.id === activeId)!;
    const already = (charts.find((c) => c.id === activeId)?.memberDigests ?? []).includes(star.digestHex);
    set({ stars, charts: chartsNext, activeId, packed: already ? get().packed : null });
    return {
      digest: star.digestHex,
      chartName: chart.name,
      count: chart.memberDigests.length,
      already,
    };
  },

  addTo: (chartId, digest) => {
    set({
      packed: null,
      charts: get().charts.map((c) => {
        if (c.id !== chartId) return c;
        if (c.memberDigests.includes(digest)) return c;
        if (c.memberDigests.length >= MAX_STARS) return c;
        return { ...c, memberDigests: [...c.memberDigests, digest] };
      }),
    });
  },

  removeFrom: (chartId, digest) => {
    set({
      packed: null,
      charts: get().charts.map((c) =>
        c.id === chartId ? { ...c, memberDigests: c.memberDigests.filter((d) => d !== digest) } : c,
      ),
    });
  },

  createChart: (name, work = null) => {
    const c: SkyChart = { id: nid(), name: name.trim() || "New sky", memberDigests: [], work };
    set({ charts: [...get().charts, c], activeId: c.id, packed: null });
    return c;
  },

  setActive: (id) => set({ activeId: id, packed: null }),

  renameActive: (name) => {
    const id = get().activeId;
    if (!id) return;
    set({
      charts: get().charts.map((c) => (c.id === id ? { ...c, name: name.trim() || c.name } : c)),
    });
  },

  setWork: (chartId, work) => {
    set({
      charts: get().charts.map((c) => (c.id === chartId ? { ...c, work } : c)),
    });
  },

  setPacked: (g) => set({ packed: g }),

  ingestChart: (title, members, work) => {
    const stars = { ...get().stars };
    const digests: string[] = [];
    for (const m of members) {
      const star = asStar(m);
      const prev = stars[star.digestHex];
      stars[star.digestHex] = prev && prev.bytes.length && !star.bytes.length ? prev : star;
      digests.push(star.digestHex);
    }
    const c: SkyChart = {
      id: nid(),
      name: title.trim() || "Opened sky",
      memberDigests: digests,
      work,
    };
    set({ stars, charts: [...get().charts, c], activeId: c.id, packed: null });
  },

  hydrateActive: (members, work) => {
    const stars = { ...get().stars };
    const digests: string[] = [];
    for (const m of members) {
      const star = asStar(m);
      const prev = stars[star.digestHex];
      stars[star.digestHex] = prev && prev.bytes.length && !star.bytes.length ? prev : star;
      digests.push(star.digestHex);
    }
    const id = get().activeId;
    set({
      stars,
      packed: get().packed,
      charts: get().charts.map((c) =>
        c.id === id ? { ...c, memberDigests: digests, work: work ?? c.work } : c,
      ),
    });
  },

  clearActive: () => {
    const id = get().activeId;
    if (!id) return;
    set({
      charts: get().charts.filter((c) => c.id !== id),
      activeId: get().charts.find((c) => c.id !== id)?.id ?? null,
      packed: null,
    });
  },
}));
