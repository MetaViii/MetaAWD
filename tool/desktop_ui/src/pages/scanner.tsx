import { useEffect, useState } from "react"
import { ChevronLeft, ChevronRight, Download, FileSearch, ScanSearch, ShieldEllipsis } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Switch } from "@/components/ui/switch"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Busy, Confirm, Empty, Field, LogPanel, Message, PageHeading, Panel, PathInput, Status, type Workspace } from "@/components/workspace"
import { callDesktop, errorText, type ScanPage } from "@/lib/desktop"

const pageSize = 100

export function ScannerPage({ workspace }: { workspace: Workspace }) {
  const { state, busy, run, pick } = workspace
  const [mode, setMode] = useState<"local" | "remote">("local")
  const [localPath, setLocalPath] = useState("")
  const [remotePath, setRemotePath] = useState("/var/www/html/")
  const [thresholdDraft, setThresholdDraft] = useState<string | null>(null)
  const [autoDelete, setAutoDelete] = useState(false)
  const [offset, setOffset] = useState(0)
  const [results, setResults] = useState<ScanPage | null>(null)
  const [readError, setReadError] = useState("")
  const job = state?.job
  const scan = state?.scan
  const plan = state?.plan
  const thresholdText = thresholdDraft ?? String(state?.scanDefaults.threshold ?? 200)
  const threshold = Number(thresholdText)
  const validThreshold = Number.isSafeInteger(threshold) && threshold > 0
  const target = mode === "local" ? localPath : remotePath
  const canScan = Boolean(state && !busy && target.trim() && validThreshold && (mode === "local" || state.connection))
  const done = scan?.status === "done"
  const matchingHost = scan?.mode !== "remote"
    || Boolean(scan.host && state?.connection && scan.host.host === state.connection.host
      && scan.host.port === state.connection.port && scan.host.user === state.connection.user)
  const canComment = done && matchingHost && scan.malicious > scan.removed

  function startScan(confirmed = false) {
    setOffset(0)
    void run("scan", { mode, target, threshold, autoDelete, confirmed })
  }

  useEffect(() => {
    let ignore = false
    setResults(null)
    setReadError("")
    if (scan?.status === "done") {
      callDesktop("scan_results", offset).then((data) => {
        if (!ignore) setResults(data)
      }).catch((error) => {
        if (!ignore) setReadError(errorText(error))
      })
    }
    return () => { ignore = true }
  }, [scan?.id, scan?.status, offset])

  async function pickTarget(kind: "file" | "directory") {
    const path = await pick(kind)
    if (path) setLocalPath(path)
  }

  return (
    <>
      <PageHeading title="WebShell 查杀" description="使用项目现有的规则库扫描本地文件或服务器目录。" />
      <Panel title="扫描设置">
        <form className="grid gap-4" onSubmit={(event) => {
          event.preventDefault()
          if (canScan && !autoDelete) startScan()
        }}>
          <ToggleGroup type="single" value={mode} variant="outline" aria-label="扫描范围"
            onValueChange={(value) => { if (value === "local" || value === "remote") setMode(value) }}>
            <ToggleGroupItem value="local">本地扫描</ToggleGroupItem>
            <ToggleGroupItem value="remote">SSH 远端扫描</ToggleGroupItem>
          </ToggleGroup>
          <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_8rem]">
            <Field label={mode === "local" ? "本地扫描路径" : "服务器扫描目录"}>
              {(id) => <PathInput id={id} value={target} onChange={mode === "local" ? setLocalPath : setRemotePath}
                placeholder={mode === "local" ? "选择目录或输入文件路径" : "/var/www/html/"}
                pick={mode === "local" ? () => void pickTarget("directory") : undefined} />}
            </Field>
            <Field label="恶意判定阈值">
              {(id) => <Input id={id} type="number" required min={1} value={thresholdText}
                onChange={(event) => setThresholdDraft(event.target.value)} />}
            </Field>
          </div>
          <Field label="自动删除恶意文件" hint="仅处理本次扫描判为恶意且复核仍达标的文件。先备份，再从原路径移除。">
            {(id) => <Switch id={id} checked={autoDelete} disabled={busy} onCheckedChange={setAutoDelete} />}
          </Field>
          <div className="flex flex-wrap items-center gap-2">
            {autoDelete ? <Confirm title="确认扫描后自动删除"
              description={`本次扫描目标为 ${target}。只移除复核后仍为恶意且已完整备份的文件。移除可能影响业务。`}
              label="确认扫描与移除" disabled={!canScan} onConfirm={() => startScan(true)}>
              {job === "scan" ? <Busy label="扫描中" /> : <><ScanSearch />开始扫描</>}
            </Confirm> : <Button type="submit" disabled={!canScan}>
              {job === "scan" ? <Busy label="扫描中" /> : <><ScanSearch />开始扫描</>}
            </Button>}
            {mode === "local" && <Button type="button" variant="ghost" disabled={!state}
              onClick={() => void pickTarget("file")}>选择单个文件</Button>}
            {mode === "remote" && !state?.connection && <small className="text-muted-foreground">请先验证 SSH 连接。</small>}
          </div>
        </form>
      </Panel>
      <Panel title="处置与报告">
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" disabled={busy || !canComment} onClick={() => void run("plan-quarantine")}>
            {job === "plan-quarantine" ? <Busy label="生成预览" /> : <><ShieldEllipsis />注释危险代码</>}
          </Button>
          <Button variant="outline" disabled={busy || !done} onClick={() => void run("report")}>
            {job === "report" ? <Busy label="保存中" /> : <><Download />保存报告</>}
          </Button>
        </div>
        <p className="mt-3 text-sm text-muted-foreground">
          {!done ? "扫描完成后可保存报告。有待处置的恶意文件时可预览注释计划。"
            : !matchingHost ? "SSH 连接已切换，重新扫描后可处置当前服务器的文件。"
              : canComment ? "注释前先预览，实际修改前会保留备份。" : "本次没有待注释的恶意文件。"}
        </p>
        {scan?.reportPath && <p role="status" className="mt-2 wrap-anywhere text-sm">报告已保存至 {scan.reportPath}</p>}
      </Panel>
      <Panel title="扫描结果" description={scan?.status === "done" ? scan.target : undefined}>
        {scan?.status === "done" ? (
          <div className="grid gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <Status>已扫描 {scan.total}</Status>
              <Status tone={scan.malicious ? "error" : "neutral"}>恶意 {scan.malicious}</Status>
              <Status tone={scan.suspicious ? "warn" : "neutral"}>可疑 {scan.suspicious}</Status>
              <Status>阈值 {scan.threshold}</Status>
              {scan.removed > 0 && <Status tone="good">已备份并移除 {scan.removed}</Status>}
              {scan.removalFailed > 0 && <Status tone="warn">跳过或未确认 {scan.removalFailed}</Status>}
            </div>
            {scan.quarantineDir && <p className="wrap-anywhere text-sm text-muted-foreground">
              备份与恢复清单保存在 {scan.quarantineDir}
            </p>}
            {readError && <Message>{readError}</Message>}
            {results?.items.length ? (
              <>
                <Table>
                  <TableHeader><TableRow><TableHead>文件</TableHead><TableHead>类型</TableHead>
                    <TableHead>分数</TableHead><TableHead>分类</TableHead></TableRow></TableHeader>
                  <TableBody>{results.items.map((item) => (
                    <TableRow key={item.file}><TableCell className="max-w-[50vw] truncate" title={item.file}>{item.file}</TableCell>
                      <TableCell>{item.type}</TableCell><TableCell>{item.score}</TableCell>
                      <TableCell><Status tone={item.verdict === "malicious" ? "error" : "warn"}>
                        {item.verdict === "malicious" ? "恶意" : "可疑"}</Status>
                        {item.removed && <Status tone="good">已移除</Status>}</TableCell></TableRow>
                  ))}</TableBody>
                </Table>
                {results.total > pageSize && <div className="flex items-center justify-end gap-2">
                  <small className="text-muted-foreground">第 {offset + 1}–{offset + results.items.length} 条，共 {results.total} 条</small>
                  <Button variant="outline" size="icon-sm" aria-label="上一页" disabled={!offset}
                    onClick={() => setOffset(offset - pageSize)}><ChevronLeft /></Button>
                  <Button variant="outline" size="icon-sm" aria-label="下一页" disabled={offset + pageSize >= results.total}
                    onClick={() => setOffset(offset + pageSize)}><ChevronRight /></Button>
                </div>}
              </>
            ) : results && <p className="text-sm text-muted-foreground">本次扫描没有发现达到阈值的文件。</p>}
          </div>
        ) : <Empty icon={<FileSearch />} title={scan?.status === "running" ? "正在扫描"
          : scan?.status === "failed" ? "扫描失败，请查看日志" : "等待开始扫描"} />}
      </Panel>
      {plan && <Panel title="注释计划" description={`计划处理 ${plan.files} 个恶意文件，修改前会先备份。`}
        actions={plan.files > 0 && <Confirm title="确认注释危险代码"
          description={`将按预览处理 ${plan.files} 个文件，并为实际修改的文件保留备份。`}
          label="确认注释" disabled={busy} onConfirm={() => void run("quarantine", { confirmed: true, scanId: plan.scanId })}>
          执行注释
        </Confirm>}>
        {plan.items.length
          ? <ScrollArea className="[&_[data-slot=scroll-area-viewport]]:max-h-72">
            <Table aria-label="注释计划"><TableBody>{plan.items.map((item) => <TableRow key={item.file}>
              <TableCell className="whitespace-normal wrap-anywhere">{item.file}</TableCell>
              <TableCell className="w-20 text-right">{item.lines} 行</TableCell>
            </TableRow>)}</TableBody></Table>
          </ScrollArea>
          : <p className="text-sm text-muted-foreground">当前没有可安全注释的代码行。</p>}
        {plan.files > plan.items.length && <small className="text-muted-foreground">预览展示前 {plan.items.length} 个文件。</small>}
      </Panel>}
      <LogPanel title="扫描日志" area="scan" events={state?.events ?? []} />
    </>
  )
}
