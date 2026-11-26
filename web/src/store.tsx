import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, ApiError, AuthError } from "./api";
import { isActive, type Action, type Host, type HostsResponse, type Job, type Status } from "./types";
import { dur, jobTitle } from "./util";

export interface Toast {
  id: number;
  text: string;
  link?: { label: string; href?: string; download?: boolean; onClick?: () => void };
  kind?: "ok" | "bad";
}

interface Ctx {
  authed: boolean | null;
  setAuthed: (v: boolean) => void;
  status: Status | null;
  data: HostsResponse | null;
  jobs: Job[];
  /** Bumped when a job finishes or hosts change, so open pages reload. */
  version: number;
  toasts: Toast[];
  toast: (t: Omit<Toast, "id">, ms?: number) => void;
  dismiss: (id: number) => void;
  refreshHosts: () => Promise<void>;
  refreshJobs: () => Promise<void>;
  refreshStatus: () => Promise<void>;
  updateHosts: (ips: string[], body: Record<string, unknown>) => Promise<boolean>;
  approveAbove: (threshold: number) => Promise<void>;
  setModel: (model: string) => Promise<boolean>;
  startJob: (action: Action, options?: Record<string, unknown>) => Promise<Job | null>;
  cancelJob: (id: string) => Promise<void>;
  jobsOpen: boolean;
  setJobsOpen: (v: boolean) => void;
  openJob: (id: string) => void;
  focusJob: string | null;
  handleError: (err: unknown) => void;
}

const AppContext = createContext<Ctx | null>(null);

export function useApp(): Ctx {
  const c = useContext(AppContext);
  if (!c) throw new Error("useApp outside AppProvider");
  return c;
}

let toastSeq = 0;

export function AppProvider({ children }: { children: ReactNode }) {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [data, setData] = useState<HostsResponse | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [version, setVersion] = useState(0);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [jobsOpen, setJobsOpen] = useState(false);
  const [focusJob, setFocusJob] = useState<string | null>(null);
  const prevJobs = useRef<Map<string, Job["status"]>>(new Map());

  const openJob = useCallback((id: string) => {
    setFocusJob(id);
    setJobsOpen(true);
  }, []);
  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const toast = useCallback(
    (t: Omit<Toast, "id">, ms = 6000) => {
      const id = ++toastSeq;
      setToasts((list) => [...list.slice(-3), { ...t, id }]);
      window.setTimeout(() => dismiss(id), ms);
    },
    [dismiss],
  );
  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof AuthError) setAuthed(false);
      else toast({ text: err instanceof Error ? err.message : String(err), kind: "bad" });
    },
    [toast],
  );

  const refreshHosts = useCallback(async () => {
    try {
      setData(await api<HostsResponse>("hosts"));
      setAuthed(true);
    } catch (err) {
      if (err instanceof AuthError) setAuthed(false);
      else handleError(err);
    }
  }, [handleError]);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api<Status>("status"));
    } catch (err) {
      if (err instanceof AuthError) setAuthed(false);
    }
  }, []);

  const refreshJobs = useCallback(async () => {
    let list: Job[];
    try {
      list = (await api<{ jobs: Job[] }>("jobs")).jobs;
    } catch (err) {
      if (err instanceof AuthError) setAuthed(false);
      return;
    }
    const finished: Job[] = [];
    for (const j of list) {
      const before = prevJobs.current.get(j.id);
      if (before && (before === "queued" || before === "running") && !isActive(j)) finished.push(j);
    }
    prevJobs.current = new Map(list.map((j) => [j.id, j.status]));
    setJobs(list);
    if (finished.length) {
      setVersion((v) => v + 1);
      refreshHosts();
      for (const j of finished) {
        if (j.status === "done") {
          const href = j.action === "apply" || j.action === "plan" ? "#/plan" : "#/hosts";
          toast({ text: `${jobTitle(j)} finished in ${dur(j.seconds)}.`, kind: "ok", link: j.action === "apply" ? { label: "Show log", onClick: () => openJob(j.id) } : { label: "Open", href } }, 10000);
        } else if (j.status === "failed") {
          toast({ text: `${jobTitle(j)} failed (exit ${j.exit_code}).`, kind: "bad", link: { label: "Show log", onClick: () => openJob(j.id) } }, 12000);
        }
      }
    }
  }, [refreshHosts, toast, openJob]);

  const updateHosts = useCallback(
    async (ips: string[], body: Record<string, unknown>) => {
      try {
        const r = ips.length === 1
          ? { hosts: [await api<Host>(`hosts/${encodeURIComponent(ips[0])}`, { method: "POST", body })] }
          : await api<{ hosts: Host[] }>("hosts", { method: "POST", body: { ...body, ips } });
        const changed = new Map(r.hosts.map((h) => [h.ip, h]));
        setData((d) => {
          if (!d) return d;
          const hosts = d.hosts.map((h) => changed.get(h.ip) ?? h);
          const counts = { pending: 0, approved: 0, rejected: 0 };
          for (const h of hosts) counts[h.decision]++;
          return { ...d, hosts, counts };
        });
        setVersion((v) => v + 1);
        return true;
      } catch (err) {
        handleError(err);
        return false;
      }
    },
    [handleError],
  );

  const approveAbove = useCallback(
    async (threshold: number) => {
      try {
        const r = await api<{ approved: number }>("review/approve-above", { method: "POST", body: { threshold } });
        toast({ text: r.approved ? `Approved ${r.approved} hosts identified with at least ${Math.round(threshold * 100)}% confidence.` : "No pending hosts are that certain.", kind: r.approved ? "ok" : undefined });
        await refreshHosts();
        setVersion((v) => v + 1);
      } catch (err) {
        handleError(err);
      }
    },
    [toast, refreshHosts, handleError],
  );

  const setModel = useCallback(
    async (model: string) => {
      try {
        const r = await api<{ model: string; model_source: string }>("settings", { method: "POST", body: { model } });
        await refreshStatus();
        toast({ text: r.model_source === "ui" ? `New scans use ${r.model}.` : `Back to the default model, ${r.model}.`, kind: "ok" });
        return true;
      } catch (err) {
        handleError(err);
        return false;
      }
    },
    [refreshStatus, toast, handleError],
  );

  const startJob = useCallback(
    async (action: Action, options: Record<string, unknown> = {}) => {
      try {
        const j = await api<Job>("jobs", { method: "POST", body: { action, options } });
        await refreshJobs();
        const now = await api<Job>(`jobs/${j.id}`).catch(() => j);
        const where = now.position ? `queued (#${now.position} in the queue)` : "started";
        toast({ text: `${jobTitle(j)} ${where}. It keeps running if you leave.`, link: { label: "Log", onClick: () => openJob(j.id) } }, 5000);
        return j;
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) toast({ text: err.message });
        else handleError(err);
        return null;
      }
    },
    [refreshJobs, toast, handleError, openJob],
  );

  const cancelJob = useCallback(
    async (id: string) => {
      try {
        await api(`jobs/${id}/cancel`, { method: "POST" });
        await refreshJobs();
      } catch (err) {
        handleError(err);
      }
    },
    [refreshJobs, handleError],
  );

  useEffect(() => {
    refreshHosts();
  }, [refreshHosts]);
  useEffect(() => {
    if (!authed) return;
    refreshStatus();
    refreshJobs();
    const t = window.setInterval(refreshStatus, 30000);
    return () => window.clearInterval(t);
  }, [authed, refreshStatus, refreshJobs]);
  const anyActive = jobs.some(isActive);
  useEffect(() => {
    if (!authed) return;
    const t = window.setInterval(refreshJobs, anyActive ? 1200 : 6000);
    return () => window.clearInterval(t);
  }, [authed, anyActive, refreshJobs]);
  useEffect(() => {
    const running = jobs.filter(isActive).length;
    document.title = running ? `(${running}) labscout` : "labscout";
  }, [jobs]);

  const value = useMemo<Ctx>(
    () => ({ authed, setAuthed, status, data, jobs, version, toasts, toast, dismiss, refreshHosts, refreshJobs, refreshStatus, updateHosts, approveAbove, setModel, startJob, cancelJob, jobsOpen, setJobsOpen, openJob, focusJob, handleError }),
    [authed, status, data, jobs, version, toasts, toast, dismiss, refreshHosts, refreshJobs, refreshStatus, updateHosts, approveAbove, setModel, startJob, cancelJob, jobsOpen, openJob, focusJob, handleError],
  );
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export type Page = "hosts" | "plan" | "scan";

/** `#/hosts[/<ip>]`, `#/plan`, `#/scan` routing. */
export function parseRoute(hash: string): { page: Page; ip: string | null } {
  const m = hash.match(/^#\/(hosts|plan|scan)(?:\/([^/]+))?/);
  if (!m) return { page: "hosts", ip: null };
  return { page: m[1] as Page, ip: m[1] === "hosts" && m[2] ? decodeURIComponent(m[2]) : null };
}

export function useRoute() {
  const [route, setRoute] = useState(() => parseRoute(location.hash));
  useEffect(() => {
    const on = () => setRoute(parseRoute(location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export const go = (page: Page, ip?: string | null) => {
  location.hash = `#/${page}${ip ? "/" + encodeURIComponent(ip) : ""}`;
};
