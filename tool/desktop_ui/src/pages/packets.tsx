import { useEffect, useId, useMemo, useState } from "react"
import { ArrowDownToLine, ChevronLeft, ChevronRight, FileText, Info, RefreshCw, ScrollText, Search, ShieldCheck, Trash2 } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Field as UiField, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group"
import { Item, ItemContent, ItemDescription, ItemGroup, ItemTitle } from "@/components/ui/item"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Busy, Confirm, Empty, Field, LogPanel, Message, PageHeading, Panel, Status, type Workspace } from "@/components/workspace"
import { callDesktop, defaultWaf, errorText, timeOf, type Packet, type PacketArea, type PacketDecision, type PacketPreview } from "@/lib/desktop"

const decisions: Record<PacketDecision, string> = {
  matched: "命中规则",
  redirected: "已重定向",
  terminated: "已结束请求",
  observed: "未命中",
  unknown: "无判定信息",
}
const areas: Record<PacketArea, string> = {
  get: "查询参数", post: "表单字段", headers: "请求头", raw_body: "正文", files: "上传信息",
}
const pageSize = 40

function decisionBadge(decision: PacketDecision) {
  const tone = decision === "redirected" || decision === "terminated" ? "error"
    : decision === "matched" ? "warn" : "neutral"
  return <Status tone={tone}>{decisions[decision]}</Status>
}

function requestTime(packet: Packet) {
  return new Date((packet.capturedAt ?? packet.mtime) * 1000).toLocaleString("zh-CN", { hour12: false })
}

function splitHttp(text: string) {
  const separator = /\r?\n\r?\n/.exec(text)
  const head = separator ? text.slice(0, separator.index) : text
  const lineEnd = head.indexOf("\n")
  return {
    headers: lineEnd < 0 ? "" : head.slice(lineEnd + 1),
    body: separator ? text.slice(separator.index + separator[0].length) : "",
    foundBodyBoundary: !!separator,
  }
}

type PacketsPageProps = { workspace: Workspace; openWaf: () => void; hitReview: number }

export function PacketsPage(props: PacketsPageProps) {
  const { workspace } = props
  const key = JSON.stringify(workspace.state?.connection ?? null)
  return <PacketViewer key={key} {...props} />
}

function PacketViewer({ workspace: { state, busy, pending, run }, openWaf, hitReview }: PacketsPageProps) {
  const syncId = useId()
  const [logDirDraft, setLogDirDraft] = useState<string | null>(null)
  const [files, setFiles] = useState<Packet[]>([])
  const [selected, setSelected] = useState("")
  const [issue, setIssue] = useState("")
  const [refresh, setRefresh] = useState(0)
  const [query, setQuery] = useState("")
  const [filter, setFilter] = useState("all")
  const [page, setPage] = useState(0)
  const ready = !!state
  const sync = state?.packetSync
  const autoEnabled = sync?.enabled ?? false
  const syncing = state?.job === "sync-packets" || state?.job === "auto-sync-packets"
  const logDir = sync?.directory ?? logDirDraft ?? state?.waf.logDir ?? defaultWaf.logDir

  useEffect(() => {
    let ignore = false
    if (ready) callDesktop("list_packets").then((items) => {
      if (!ignore) {
        setFiles(items)
        setIssue("")
      }
    }).catch((error) => {
      if (!ignore) setIssue(errorText(error))
    })
    return () => { ignore = true }
  }, [ready, sync?.revision, refresh])

  useEffect(() => {
    if (hitReview) {
      setFilter("hit")
      setQuery("")
      setPage(0)
      setSelected("")
    }
  }, [hitReview])

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return files.filter((packet) => {
      if (filter === "hit" && (packet.decision === "unknown" || packet.decision === "observed")) return false
      if (filter !== "all" && filter !== "hit" && filter !== packet.decision) return false
      const searchFields = [packet.method, packet.target, packet.peer, packet.name]
      return !needle || searchFields.some((field) => field?.toLowerCase().includes(needle))
    })
  }, [files, filter, query])
  const currentPage = Math.max(0, Math.min(page, Math.ceil(filtered.length / pageSize) - 1))
  const start = currentPage * pageSize
  const visible = filtered.slice(start, start + pageSize)
  const packet = filtered.find((item) => item.name === selected) ?? visible[0]
  const packetName = packet?.name ?? ""
  useEffect(() => {
    if (selected !== packetName) setSelected(packetName)
  }, [packetName, selected])

  return (
    <>
      <PageHeading title="请求审查" description="查看到达 PHP WAF 的 HTTP 请求与处理记录。"
        actions={<Button variant="outline" disabled={!ready} onClick={() => setRefresh((value) => value + 1)}><RefreshCw />刷新本地</Button>} />
      <Panel title="远端同步"
        actions={<>
          <UiField orientation="horizontal" className="w-auto items-center gap-2">
            <FieldLabel htmlFor={syncId} className="text-xs font-medium">自动同步</FieldLabel>
            <Switch id={syncId} checked={autoEnabled} disabled={!state?.connection || pending}
              onCheckedChange={(enabled) => void run("set-packet-auto-sync", { enabled, logDir })} />
          </UiField>
          <Button size="sm" variant="ghost" onClick={openWaf}><ShieldCheck />WAF 设置</Button>
        </>}>
        <form className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-end"
          onSubmit={(event) => { event.preventDefault(); void run("sync-packets", { logDir }) }}>
          <Field label="远端日志目录">
            {(id) => <Input id={id} value={logDir} onChange={(event) => setLogDirDraft(event.target.value)}
              readOnly={autoEnabled} spellCheck={false} />}
          </Field>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" disabled={!state?.connection || busy}>
              {syncing ? <Busy label="同步中" /> : <><ArrowDownToLine />同步请求</>}
            </Button>
            <Confirm title="清空本地请求日志" label="清空日志" disabled={!files.length || busy}
              description={`将删除当前服务器在本机保存的 ${files.length} 条请求日志。`}
              onConfirm={() => void run("clear-packets", { confirmed: true })}><Trash2 />清空本地</Confirm>
            {state?.waf.deployed && <Status>{state.waf.logAll ? "记录全部请求" : "仅记录命中"}</Status>}
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground md:col-span-2">
            <p>同步会先保存到本机，再清理已下载的远端日志。</p>
            <p>{!state?.connection ? "验证 SSH 后可开启自动同步。"
              : autoEnabled ? `每 ${sync?.interval ?? 5} 秒检查${sync?.lastCheckedAt && !sync.error
                ? ` · 最近检查 ${timeOf(sync.lastCheckedAt)}` : ""}`
                : `自动同步开启后每 ${sync?.interval ?? 5} 秒检查一次。`}</p>
          </div>
        </form>
        {sync?.error && <div className="mt-3">
          <Message>{sync.error}{autoEnabled ? `。将在 ${sync.retryInterval} 秒后重试。` : ""}</Message>
        </div>}
      </Panel>
      {issue && <Message>{issue}</Message>}
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <Panel title="请求列表" actions={<Status>{filtered.length} / {files.length} 条</Status>} className="min-w-0">
          <div className="mb-4 flex flex-wrap gap-2">
            <InputGroup className="min-w-44 flex-1">
              <InputGroupAddon><Search /></InputGroupAddon>
              <InputGroupInput aria-label="搜索请求" placeholder="方法、路径、对端 IP"
                value={query} onChange={(event) => { setQuery(event.target.value); setPage(0) }} />
            </InputGroup>
            <NativeSelect value={filter} aria-label="按 WAF 结果筛选"
              onChange={(event) => { setFilter(event.target.value); setPage(0) }}>
              <NativeSelectOption value="all">全部结果</NativeSelectOption>
              <NativeSelectOption value="hit">规则命中</NativeSelectOption>
              <NativeSelectOption value="observed">未命中</NativeSelectOption>
              <NativeSelectOption value="unknown">无判定信息</NativeSelectOption>
            </NativeSelect>
          </div>
          {visible.length
            ? <ScrollArea className="[&_[data-slot=scroll-area-viewport]]:max-h-[30rem]">
              <ItemGroup role="group" aria-label="已同步请求" className="gap-1">
                {visible.map((item) => (
                  <Item asChild size="sm" className="px-3 aria-[current=true]:bg-accent" key={item.name}>
                    <a href="#request" aria-current={item.name === packet?.name ? "true" : undefined}
                      onClick={(event) => { event.preventDefault(); setSelected(item.name) }}>
                      <ItemContent className="min-w-0">
                        <ItemTitle className="w-full min-w-0">
                          {item.method && <Badge variant="outline" className="font-mono">{item.method}</Badge>}
                          <span className="truncate font-mono" title={item.target ?? item.name}>{item.target ?? item.name}</span>
                        </ItemTitle>
                        <ItemDescription className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
                          <time>{requestTime(item)}</time>
                          <span>{item.peer ?? "对端未知"}</span>
                          {decisionBadge(item.decision)}
                        </ItemDescription>
                      </ItemContent>
                    </a>
                  </Item>
                ))}
              </ItemGroup>
            </ScrollArea>
            : <Empty icon={<ScrollText />} title={files.length ? "没有符合条件的请求" : "暂无本地请求日志"}>
              {!files.length && "部署 WAF 后同步请求。需要查看未命中的请求时，在部署设置中开启「记录全部请求」。"}
            </Empty>}
          {filtered.length > pageSize && <div className="mt-4 flex flex-wrap items-center justify-end gap-2">
            <small className="text-muted-foreground">第 {start + 1}–{start + visible.length} 条</small>
            <Button size="icon-sm" variant="outline" aria-label="上一页" disabled={!currentPage}
              onClick={() => { setSelected(""); setPage(currentPage - 1) }}><ChevronLeft /></Button>
            <Button size="icon-sm" variant="outline" aria-label="下一页" disabled={start + pageSize >= filtered.length}
              onClick={() => { setSelected(""); setPage(currentPage + 1) }}><ChevronRight /></Button>
          </div>}
        </Panel>
        {packet ? <RequestDetails key={packet.name} packet={packet} />
          : <Panel title="请求详情"><Empty icon={<FileText />} title="请选择一条请求" /></Panel>}
      </div>
      <LogPanel title="同步日志" area="packets" events={state?.events ?? []} />
    </>
  )
}

function RequestDetails({ packet }: { packet: Packet }) {
  const [preview, setPreview] = useState<PacketPreview | null>(null)
  const [readError, setReadError] = useState("")
  const [exportError, setExportError] = useState("")
  const [saved, setSaved] = useState("")
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    let ignore = false
    setReadError("")
    callDesktop("read_packet", packet.name).then((data) => {
      if (!ignore) setPreview(data)
    }).catch((error) => {
      if (!ignore) {
        setPreview(null)
        setReadError(errorText(error))
      }
    })
    return () => { ignore = true }
  }, [packet])

  async function saveRaw() {
    setSaving(true)
    setExportError("")
    setSaved("")
    try {
      const path = await callDesktop("export_packet", packet.name)
      if (path) setSaved(path)
    } catch (error) {
      setExportError(errorText(error))
    } finally {
      setSaving(false)
    }
  }

  const { headers, body, foundBodyBoundary } = splitHttp(preview?.text ?? "")
  return (
    <Panel title="请求详情" className="min-w-0"
      actions={<Button size="sm" variant="outline" onClick={() => void saveRaw()} disabled={saving || !preview}>
        {saving ? <Busy label="保存中" /> : <><ArrowDownToLine />保存 HTTP 原文</>}
      </Button>}>
      <div className="grid gap-4">
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <div><dt className="text-xs text-muted-foreground">{packet.capturedAt ? "请求时间" : "文件时间"}</dt>
            <dd><time>{requestTime(packet)}</time></dd></div>
          <div><dt className="text-xs text-muted-foreground">PHP 对端 IP</dt>
            <dd className="font-mono wrap-anywhere">{packet.peer ?? "此日志未记录"}</dd></div>
          <div><dt className="mb-1 text-xs text-muted-foreground">WAF 处理</dt>
            <dd>{decisionBadge(packet.decision)}</dd></div>
          {!!packet.matchedAreas.length && <div><dt className="mb-1 text-xs text-muted-foreground">命中位置</dt>
            <dd className="flex flex-wrap gap-1">{packet.matchedAreas.map((area) => <Badge variant="outline" key={area}>{areas[area]}</Badge>)}</dd></div>}
        </dl>
        {readError && <Message>{readError}</Message>}
        {exportError && <Message>{exportError}</Message>}
        {saved && <p role="status" className="text-sm wrap-anywhere text-muted-foreground">原文已保存到 {saved}</p>}
        {preview && <>
          {(preview.truncated || preview.hasBinary) && <Alert><Info /><AlertDescription>
            {preview.truncated && "预览显示前 64 KiB。"}{preview.hasBinary && "有字节无法以 UTF-8 文本显示。"}保存 HTTP 原文可取得完整采集字节。
          </AlertDescription></Alert>}
          <Tabs defaultValue="raw">
            <TabsList aria-label="请求内容">
              <TabsTrigger value="raw">原文</TabsTrigger>
              <TabsTrigger value="headers">请求头</TabsTrigger>
              <TabsTrigger value="body">正文</TabsTrigger>
            </TabsList>
            <TabsContent value="raw"><RequestText label="HTTP 原文" text={preview.text || "日志为空。"} /></TabsContent>
            <TabsContent value="headers"><RequestText label="请求头" text={headers || "日志未记录请求头。"} /></TabsContent>
            <TabsContent value="body"><RequestText label="请求正文" text={body || (
              !foundBodyBoundary && preview.truncated ? "正文超出当前预览范围，可保存 HTTP 原文查看。"
              : packet.bodyState === "unavailable" ? "PHP 未提供这条请求的原始正文。"
              : "日志未记录正文。"
            )} /></TabsContent>
          </Tabs>
        </>}
        {!preview && !readError && <p className="flex items-center gap-2 text-sm text-muted-foreground"><Busy label="正在读取请求" /></p>}
      </div>
    </Panel>
  )
}

function RequestText({ label, text }: { label: string; text: string }) {
  return <Textarea aria-label={label} readOnly value={text}
    className="h-72 resize-y border-border bg-muted font-mono text-xs leading-relaxed shadow-none dark:bg-muted" />
}
