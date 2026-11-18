import { useEffect, useState } from "react"
import { CircleStop, ClipboardCheck, Download, Flag, Send } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { Busy, Empty, Field, Message, PageHeading, Panel, Status, type Workspace } from "@/components/workspace"
import { callDesktop, errorText, type BugkuOptions, type BugkuPreview, type BugkuResult } from "@/lib/desktop"

const maxInput = 65536

const resultLabels = {
  accepted: { label: "已确认", tone: "good" },
  duplicate: { label: "已提交过", tone: "neutral" },
  rejected: { label: "被拒绝", tone: "error" },
  unknown: { label: "待确认", tone: "warn" },
  skipped: { label: "未发送", tone: "neutral" },
} as const

export function BugkuPage({ workspace: { state, run, pending }, active }: {
  workspace: Workspace
  active: boolean
}) {
  const [token, setToken] = useState("")
  const [flags, setFlags] = useState("")
  const [interval, setInterval] = useState("250")
  const [timeout, setTimeout] = useState("5")
  const [limit, setLimit] = useState("256")
  const [duplicates, setDuplicates] = useState<BugkuOptions["duplicates"]>("skip")
  const [preview, setPreview] = useState<BugkuPreview | null>(null)
  const [checking, setChecking] = useState(false)
  const [importing, setImporting] = useState(false)
  const [formIssue, setFormIssue] = useState("")
  const [results, setResults] = useState<BugkuResult[]>([])
  const [readIssue, setReadIssue] = useState("")
  const [exporting, setExporting] = useState(false)
  const [exportIssue, setExportIssue] = useState("")
  const [savedPath, setSavedPath] = useState("")
  const batch = state?.bugku
  const revision = batch?.revision
  const running = batch?.running ?? false
  const stopping = batch?.stopping ?? false
  const locked = running || pending || checking || importing
  const options: BugkuOptions = {
    intervalMs: Number(interval), timeoutSeconds: Number(timeout), maxFlags: Number(limit), duplicates,
  }

  function clearPreview() {
    setPreview(null)
    setFormIssue("")
  }

  async function importFlags(file: File) {
    clearPreview()
    setImporting(true)
    try {
      if (!file.name.toLowerCase().endsWith(".txt") || file.size > maxInput * 4) {
        throw new Error("请选择 UTF-8 编码的 TXT 文件，最多 65536 个字符。")
      }
      const text = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer())
      if (text.length > maxInput) throw new Error("TXT 内容超过 65536 个字符。")
      setFlags(text)
    } catch {
      setFormIssue("无法导入文件。请选择 UTF-8 编码的 TXT，最多 65536 个字符。")
    } finally {
      setImporting(false)
    }
  }

  async function checkBatch() {
    clearPreview()
    setChecking(true)
    try {
      setPreview(await callDesktop("bugku_preview", flags, options))
    } catch (error) {
      setFormIssue(errorText(error))
    } finally {
      setChecking(false)
    }
  }

  async function saveResults() {
    setExporting(true)
    setExportIssue("")
    try {
      const path = await callDesktop("export_bugku")
      if (path) setSavedPath(path)
    } catch (error) {
      setExportIssue(errorText(error))
    } finally {
      setExporting(false)
    }
  }

  useEffect(() => {
    if (!active || revision === undefined) return
    let ignore = false
    callDesktop("bugku_results").then((rows) => {
      if (!ignore) {
        setResults(rows)
        setReadIssue("")
      }
    }).catch((error) => {
      if (!ignore) setReadIssue(errorText(error))
    })
    return () => { ignore = true }
  }, [active, revision])

  return (
    <>
      <PageHeading title="Bugku 批量提交" description="将你已取得的 flag 批量提交到 Bugku PVP 计分端。"
        actions={running && <Status tone="warn">{stopping ? "正在停止" : "提交中"}</Status>} />
      <div className="grid items-start gap-4 xl:grid-cols-2">
        <Panel title="提交批次">
          <form className="grid gap-4" onSubmit={async (event) => {
            event.preventDefault()
            if (locked) return
            setSavedPath("")
            setExportIssue("")
            if (await run("bugku-submit", { token, flags, options })) setToken("")
          }}>
            <Field label="队伍 Token">
              {(id) => <Input id={id} type="password" required maxLength={256} autoComplete="off"
                value={token} onChange={(event) => setToken(event.target.value)} disabled={locked} />}
            </Field>
            <Field label="导入 TXT" hint="从本机选择 UTF-8 文件，导入后替换当前列表。">
              {(id) => <Input id={id} type="file" accept=".txt,text/plain" disabled={locked}
                onChange={(event) => {
                  const file = event.currentTarget.files?.[0]
                  event.currentTarget.value = ""
                  if (file) void importFlags(file)
                }} />}
            </Field>
            <Field label="Flag 列表" hint="每行一条，空行会跳过。">
              {(id) => <Textarea id={id} required spellCheck={false} maxLength={maxInput}
                value={flags} onChange={(event) => {
                  setFlags(event.target.value)
                  clearPreview()
                }} disabled={locked}
                placeholder="在此粘贴已有的 flag" className="min-h-44 resize-y font-mono" />}
            </Field>
            <Separator />
            <fieldset disabled={locked} className="grid gap-4 sm:grid-cols-2">
              <legend className="mb-3 text-sm font-medium">提交参数</legend>
              <Field label="提交间隔（毫秒）" hint="上一条结束后等待 250–10000 毫秒。">
                {(id) => <Input id={id} type="number" required min={250} max={10000} value={interval}
                  onChange={(event) => {
                    setInterval(event.target.value)
                    clearPreview()
                  }} />}
              </Field>
              <Field label="请求超时（秒）" hint="连接和读取分别使用此超时。">
                {(id) => <Input id={id} type="number" required min={1} max={60} value={timeout}
                  onChange={(event) => {
                    setTimeout(event.target.value)
                    clearPreview()
                  }} />}
              </Field>
              <Field label="单批上限" hint="超过上限时先缩减列表。">
                {(id) => <Input id={id} type="number" required min={1} max={256} value={limit}
                  onChange={(event) => {
                    setLimit(event.target.value)
                    clearPreview()
                  }} />}
              </Field>
              <Field label="重复项处理">
                {(id) => <NativeSelect id={id} value={duplicates} className="w-full" onChange={(event) => {
                  setDuplicates(event.target.value === "reject" ? "reject" : "skip")
                  clearPreview()
                }}>
                  <NativeSelectOption value="skip">只提交首次出现的条目</NativeSelectOption>
                  <NativeSelectOption value="reject">发现重复项时校验失败</NativeSelectOption>
                </NativeSelect>}
              </Field>
            </fieldset>
            {formIssue && <Message>{formIssue}</Message>}
            {preview && <Alert><ClipboardCheck /><AlertDescription>
              可提交 {preview.count} 条，重复 {preview.duplicates} 条，空行 {preview.blanks} 条。
            </AlertDescription></Alert>}
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={!state || !token.trim() || !flags.trim() || locked}>
                {running ? <Busy label="提交中" /> : <><Send />提交批次</>}
              </Button>
              <Button type="button" variant="outline" disabled={!state || !flags.trim() || locked}
                onClick={() => void checkBatch()}>
                {checking ? <Busy label="校验中" /> : <><ClipboardCheck />预览批次</>}
              </Button>
              {running && <Button type="button" variant="outline" disabled={stopping || pending}
                onClick={() => void run("bugku-stop")}><CircleStop />停止后续提交</Button>}
            </div>
          </form>
        </Panel>
        <Panel title="提交结果" className="min-w-0"
          actions={<div className="flex flex-wrap items-center gap-2">
            {!!batch?.total && <Status>已处理 {batch.done} / {batch.total}</Status>}
            <Button size="sm" variant="outline" disabled={!results.length || running || exporting}
              onClick={() => void saveResults()}><Download />导出 CSV</Button>
          </div>}>
          <div className="grid gap-3">
            {readIssue && <Message>{readIssue}</Message>}
            {exportIssue && <Message>{exportIssue}</Message>}
            {savedPath && <p role="status" className="text-sm text-muted-foreground wrap-anywhere">已保存至 {savedPath}</p>}
            {!!batch?.duplicates && <p className="text-sm text-muted-foreground">已跳过 {batch.duplicates} 个重复输入。</p>}
            {results.length > 0 ? <ScrollArea className="[&_[data-slot=scroll-area-viewport]]:max-h-80">
              <Table aria-label="Bugku 提交结果">
                <TableHeader><TableRow><TableHead>输入行</TableHead><TableHead>状态</TableHead><TableHead>结果</TableHead></TableRow></TableHeader>
                <TableBody>{results.map((row) => {
                  const status = resultLabels[row.status]
                  return <TableRow key={row.line}>
                    <TableCell className="tabular-nums">{row.line}</TableCell>
                    <TableCell><Status tone={status.tone}>{status.label}</Status></TableCell>
                    <TableCell className="whitespace-normal">{row.message}</TableCell>
                  </TableRow>
                })}</TableBody>
              </Table>
            </ScrollArea> : <Empty icon={<Flag />} title={running ? "等待平台回复" : "暂无提交结果"} />}
          </div>
        </Panel>
      </div>
    </>
  )
}
