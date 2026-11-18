export type Area = "ssh" | "monitor" | "scan" | "waf" | "packets" | "backup" | "attack"
export type Connection = { host: string; port: number; user: string }
export type MonitorState = "idle" | "starting" | "running" | "paused" | "stopping"
export type Scan = {
  id: number
  mode: "local" | "remote"
  target: string
  threshold: number
  status: "running" | "done" | "failed"
  total: number
  malicious: number
  suspicious: number
  removed: number
  removalFailed: number
  quarantineDir: string | null
  reportPath: string | null
  host: Connection | null
}
export type WafConfig = {
  webRoot: string
  installDir: string
  logDir: string
  mode: number
  strict: number
  redirect: string
  logAll: boolean
}
export type EventEntry = {
  id: number
  time: number
  area: Area
  level: "info" | "error" | "success"
  message: string
}
export type PacketSync = {
  enabled: boolean
  directory: string | null
  interval: number
  retryInterval: number
  revision: number
  lastCheckedAt: number | null
  error: string | null
  hitCursor: number
  unreadHits: number
}
export type TerminalState = {
  phase: "idle" | "connecting" | "open" | "closing"
  error: string | null
  revision: number
}
export type BugkuState = {
  running: boolean
  stopping: boolean
  total: number
  done: number
  duplicates: number
  revision: number
}
export type BugkuResult = {
  line: number
  status: "accepted" | "duplicate" | "rejected" | "unknown" | "skipped"
  message: string
}
export type BugkuOptions = {
  intervalMs: number
  timeoutSeconds: number
  maxFlags: number
  duplicates: "skip" | "reject"
}
export type BugkuPreview = { count: number; blanks: number; duplicates: number }
export type AttackerShell = {
  number: number
  label: string
  urlCount: number
  payload: string
  keyMethod: "0" | "GET" | "POST"
  key: string
  keyValue: string
  cmdMethod: "GET" | "POST"
  note: string
}
export type AttackerState = {
  activeCount: number
  outputFile: string
  shells: AttackerShell[]
}
export type UrlList = { total: number; items: string[] }
export type ElfAudit = {
  path: string
  size: number
  sha256: string
  machine: string | number
  kind: string | number
  bits: number
  endian: "little" | "big"
  dynamic: boolean
  nx: "on" | "off" | "unknown"
  pie: "on" | "off" | "unknown"
  relro: "off" | "partial" | "full" | "present"
  canary: boolean
  fortify: boolean
}
export type PwnOptions = {
  unit: string
  syscalls: "inherit" | "baseline" | "service"
  filesystem: "inherit" | "full" | "strict"
  network: "inherit" | "unix" | "ip"
  writablePaths: string
  inaccessiblePaths: string
  noNewPrivileges: boolean
  privateTmp: boolean
  nativeAbi: boolean
  denyWritableExecute: boolean
  noExecTemp: boolean
}
export type PwnPolicy = {
  unit: string
  target: string
  text: string
  rules: { directive: string; effect: string }[]
  warnings: string[]
}
export type ElfBundleProfile = { id: string; label: string; description: string; syscalls: string[] }
export type ElfBundlePreset = { id: string; label: string; description: string; groups: string[] }
export type ElfBundle = { source: string; size: number; sha256: string; groups: string[]; syscalls: string[]; files: string[] }
export type Snapshot = {
  window?: { controls: boolean; maximized: boolean }
  connection: Connection | null
  terminal: TerminalState
  bugku: BugkuState
  attacker: AttackerState
  job: string | null
  jobVersion: number
  monitor: { state: MonitorState; path: string }
  scan: Scan | null
  scanDefaults: { threshold: number; suspectRatio: number; types: string[] }
  waf: WafConfig & { deployed: boolean; guard: boolean }
  backupDir: string
  packetCount: number
  packetSync: PacketSync
  plan: { scanId: number; files: number; items: { file: string; lines: number }[] } | null
  events: EventEntry[]
}
export type PacketDecision = "observed" | "matched" | "redirected" | "terminated" | "unknown"
export type PacketArea = "get" | "post" | "headers" | "raw_body" | "files"
export type Packet = {
  name: string
  mtime: number
  capturedAt: number | null
  method: string | null
  target: string | null
  peer: string | null
  decision: PacketDecision
  bodyState: "captured" | "empty" | "unavailable" | "unknown"
  matchedAreas: PacketArea[]
}
export type PacketPreview = { text: string; truncated: boolean; hasBinary: boolean }
export type WindowCommand = "minimize" | "toggle-maximize" | "close"
export type ScanPage = {
  total: number
  items: { file: string; type: string; score: number; verdict: "malicious" | "suspicious"; removed: boolean }[]
}
type Calls = {
  attack_urls: { args: ["active" | "shell", number | null]; result: UrlList }
  snapshot: { args: []; result: Snapshot }
  window_control: { args: [WindowCommand]; result: null }
  action: { args: [string, Record<string, unknown>]; result: { ok: boolean; message?: string } }
  scan_results: { args: [number]; result: ScanPage }
  terminal_output: { args: []; result: string }
  bugku_results: { args: []; result: BugkuResult[] }
  bugku_preview: { args: [string, BugkuOptions]; result: BugkuPreview }
  export_bugku: { args: []; result: string | null }
  pwn_audit: { args: [string]; result: ElfAudit }
  pwn_plan: { args: [PwnOptions]; result: PwnPolicy }
  export_pwn_policy: { args: [PwnOptions]; result: string | null }
  pwn_bundle_profiles: { args: []; result: { runnerReady: boolean; groups: ElfBundleProfile[]; presets: ElfBundlePreset[] } }
  pwn_bundle_preview: { args: [string, string[]]; result: ElfBundle }
  export_pwn_bundle: { args: [string, string[]]; result: (ElfBundle & { directory: string }) | null }
  list_packets: { args: []; result: Packet[] }
  read_packet: { args: [string]; result: PacketPreview }
  export_packet: { args: [string]; result: string | null }
  pick_path: { args: ["directory" | "archive" | "file"]; result: string | null }
}

declare global {
  interface Window {
    pywebview?: { api?: { invoke: (method: string, args: unknown[]) => Promise<unknown> } }
  }
}

export async function callDesktop<M extends keyof Calls>(method: M, ...args: Calls[M]["args"]) {
  const api = window.pywebview?.api
  if (!api) throw new Error("请通过 MetaAWD 桌面窗口使用此操作。")
  return await api.invoke(method, args) as Calls[M]["result"]
}

export function errorText(error: unknown) {
  return error instanceof Error ? error.message : String(error)
}

export const areaLabels: Record<Area, string> = {
  ssh: "SSH 连接", monitor: "文件监控", scan: "WebShell 查杀",
  waf: "WAF 管理", packets: "请求审查", backup: "源码备份", attack: "攻击辅助",
}
export const monitorLabels: Record<MonitorState, string> = {
  idle: "未启动", starting: "正在连接", running: "运行中", paused: "已暂停", stopping: "正在停止",
}
export const defaultWaf: WafConfig = {
  webRoot: "/var/www/html/",
  installDir: "/var/www/html/.phpwaf",
  logDir: "/tmp/.phpwaf_logs",
  mode: 1,
  strict: 3,
  redirect: "/",
  logAll: false,
}
export const timeOf = (seconds: number) =>
  new Date(seconds * 1000).toLocaleTimeString("zh-CN", { hour12: false })
