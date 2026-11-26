export type Decision = "pending" | "approved" | "rejected";
export const DECISIONS: Decision[] = ["pending", "approved", "rejected"];

export interface Status {
  version: string;
  ollama_host: string;
  use_llm: boolean;
  model: string;
  model_source: "ui" | "config";
  default_model: string;
  ollama: string | null;
  ollama_error?: string;
  model_available: boolean | null;
  models: string[];
  nmap: string;
  networks: string[];
  proxmox: string[];
  netalertx: boolean;
  netbox: string;
  infra: string;
  domain: string;
  auth: boolean;
}

export interface Port {
  port: number;
  proto: string;
  service: string;
  product: string;
  version: string;
  extra: string;
}

export interface HttpInfo {
  port: number;
  scheme: string;
  status: number;
  title: string;
  server: string;
  powered_by: string;
  generator: string;
  location: string;
  body_hint: string;
}

export interface ProxmoxGuest {
  endpoint: string;
  node: string;
  vmid: number;
  type: string;
  name: string;
  status: string;
  tags: string[];
  description: string;
  ostype: string;
  cores: number;
  memory_mb: number;
}

export interface Identity {
  app: string;
  display_name: string;
  category: string;
  version: string;
  confidence: number;
  source: string;
  web_port: number;
  scheme: string;
  health_path: string;
  metrics_port: number;
  metrics_path: string;
  exporter: string;
  community_script: string;
  description: string;
  reasons: string[];
}

export interface Host {
  ip: string;
  name: string;
  mac: string;
  vendor: string;
  hostname: string;
  sources: string[];
  ports: Port[];
  http: HttpInfo[];
  proxmox: ProxmoxGuest | null;
  identity: Identity | null;
  decision: Decision;
  note: string;
}

export interface HostsResponse {
  hosts: Host[];
  counts: Record<Decision, number>;
  scanned: number | null;
}

export interface MonitoringEntry {
  host: string;
  ip: string;
  app: string;
  check: string;
  metrics: string;
  exporter: string;
  node_exporter: boolean;
}

export interface NetboxEntry {
  ip: string;
  cidr: string;
  dns_name: string;
  description: string;
  vm: string;
  services: { name: string; port: number; description: string }[];
}

export interface UnknownEntry {
  ip: string;
  name: string;
  vendor: string;
  ports: number[];
  guess: string;
}

export interface Plan {
  catalog_add: Record<string, Record<string, unknown>>;
  aliases_add: Record<string, string>;
  monitoring: MonitoringEntry[];
  netbox: NetboxEntry[];
  unknown: UnknownEntry[];
  skipped: string[];
}

export interface PlanResponse {
  plan: Plan;
  report: string;
  include_pending: boolean;
}

export type Action = "run" | "scan" | "identify" | "plan" | "apply";

export interface Job {
  id: string;
  action: Action;
  options: Record<string, unknown>;
  status: "queued" | "running" | "done" | "failed" | "cancelled";
  dry_run: boolean;
  exit_code: number | null;
  created: number;
  started: number | null;
  ended: number | null;
  seconds: number;
  position: number | null;
  lines?: string[];
  next?: number;
}

export const isActive = (j: Pick<Job, "status">) => j.status === "queued" || j.status === "running";
