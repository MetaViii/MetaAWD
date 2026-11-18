import { useState } from "react"
import { Cable, CircleStop, Pause, Play } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Busy, Field, LogPanel, PageHeading, Panel, PathInput, Status, type Workspace } from "@/components/workspace"
import { monitorLabels } from "@/lib/desktop"

export function ConnectionPage({ workspace }: { workspace: Workspace }) {
  const { state, busy, run } = workspace
  const [host, setHost] = useState(state?.connection?.host ?? "")
  const [port, setPort] = useState(String(state?.connection?.port ?? 22))
  const [user, setUser] = useState(state?.connection?.user ?? "root")
  const [password, setPassword] = useState("")
  const testing = state?.job === "connect"

  return (
    <>
      <PageHeading title="SSH 连接" description="验证用于交互终端、文件监控、远端查杀和 WAF 管理的服务器。"
        actions={<Status tone={state?.connection ? "good" : "neutral"}>{state?.connection
          ? `${state.connection.user}@${state.connection.host}:${state.connection.port}`
          : "未连接"}</Status>} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="连接配置">
          <form className="grid gap-4" onSubmit={async (event) => {
            event.preventDefault()
            if (await run("connect", { host, port: Number(port), user, password })) setPassword("")
          }}>
            <div className="grid grid-cols-[minmax(0,1fr)_6rem] gap-4">
              <Field label="主机地址">{(id) => <Input id={id} required value={host}
                onChange={(event) => setHost(event.target.value)}
                placeholder="主机名或 IP 地址" spellCheck={false} autoComplete="off" />}</Field>
              <Field label="端口">{(id) => <Input id={id} type="number" min={1} max={65535} required value={port}
                onChange={(event) => setPort(event.target.value)} />}</Field>
            </div>
            <Field label="用户名">{(id) => <Input id={id} required value={user}
              onChange={(event) => setUser(event.target.value)} autoComplete="off" />}</Field>
            <Field label="密码" hint="使用本机 SSH 密钥时可留空。">
              {(id) => <Input id={id} type="password" value={password} onChange={(event) => setPassword(event.target.value)}
                autoComplete="off" />}
            </Field>
            <div><Button type="submit" disabled={!state || busy}>
              {testing ? <Busy label="验证中" /> : <><Cable />测试连接</>}
            </Button></div>
          </form>
        </Panel>
        <LogPanel title="连接日志" area="ssh" events={state?.events ?? []} />
      </div>
    </>
  )
}

export function MonitorPage({ workspace }: { workspace: Workspace }) {
  const { state, busy, run } = workspace
  const [path, setPath] = useState(state?.monitor.path || "/var/www/html/")
  const phase = state?.monitor.state ?? "idle"
  const active = phase !== "idle"
  const canPause = phase === "paused" || phase === "running"
  const tone = phase === "running" ? "good" : phase === "paused" ? "warn" : "neutral"
  return (
    <>
      <PageHeading title="文件监控" description="建立站点文件基线，记录新增和修改。"
        actions={<Status tone={tone}>{monitorLabels[phase]}</Status>} />
      <Panel title="监控设置" description="检测到的变更会写入下方日志。">
        <form className="grid gap-4" onSubmit={(event) => {
          event.preventDefault()
          void run("start-monitor", { path })
        }}>
          <Field label="服务器目录">
            {(id) => <PathInput id={id} value={path} onChange={setPath} disabled={active} />}
          </Field>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" disabled={!state?.connection || active || busy}><Play />开始监控</Button>
            <Button type="button" variant="outline" disabled={!canPause || workspace.pending} onClick={() => void run("pause-monitor")}>
              {phase === "paused" ? <><Play />继续</> : <><Pause />暂停</>}
            </Button>
            <Button type="button" variant="outline" disabled={!active || phase === "stopping" || workspace.pending}
              onClick={() => void run("stop-monitor")}><CircleStop />停止</Button>
            {!state?.connection && <small className="text-muted-foreground">请先验证 SSH 连接。</small>}
          </div>
        </form>
      </Panel>
      <LogPanel title="监控日志" area="monitor" events={state?.events ?? []} />
    </>
  )
}
