import { useEffect, useState } from "react"
import { Crosshair, FileInput, Play, Radar, RefreshCw, Search, Upload } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Field as UiField, FieldContent, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import {
  Busy, Confirm, Empty, Field, LogPanel, Message, PageHeading, Panel, PathInput, Status, type Workspace,
} from "@/components/workspace"
import { callDesktop, errorText } from "@/lib/desktop"

function AttackStatus({ workspace: { state } }: { workspace: Workspace }) {
  const attack = state?.attacker
  return (
    <div className="flex flex-wrap gap-2">
      <Status tone={attack?.activeCount ? "good" : "neutral"}>存活目标 {attack?.activeCount ?? 0}</Status>
      <Status tone={attack?.shells.length ? "good" : "neutral"}>已知后门 {attack?.shells.length ?? 0}</Status>
    </div>
  )
}

/** 读取「探活目标」或「某条后门记录」中的站点，只在编号变化时重新查询。 */
function useUrls(scope: "active" | "shell", number: number | null, revision: number) {
  const [items, setItems] = useState<string[]>([])
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    let ignore = false
    setError("")
    if (scope === "shell" && number === null) {
      setItems([])
      setLoading(false)
      return
    }
    setLoading(true)
    callDesktop("attack_urls", scope, scope === "shell" ? number : null).then((data) => {
      if (!ignore) setItems(data.items)
    }).catch((failure) => {
      if (!ignore) {
        setItems([])
        const message = errorText(failure)
        // 浏览器预览没有 pywebview 桥接，这里不把离线提示当成业务错误。
        setError(message.includes("桌面窗口") ? "" : message)
      }
    }).finally(() => {
      if (!ignore) setLoading(false)
    })
    return () => { ignore = true }
  }, [scope, number, revision])

  return { items, error, loading }
}

function UrlTable({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  if (!items.length) return <Empty icon={<Radar />} title={empty} />
  return (
    <ScrollArea className="[&_[data-slot=scroll-area-viewport]]:max-h-72">
      <Table aria-label={title}>
        <TableHeader>
          <TableRow>
            <TableHead className="w-14">序号</TableHead>
            <TableHead>站点</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((url, index) => (
            <TableRow key={url}>
              <TableCell className="font-mono text-xs text-muted-foreground tabular-nums">{index + 1}</TableCell>
              <TableCell className="font-mono text-xs whitespace-normal wrap-anywhere">{url}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ScrollArea>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 font-mono text-xs wrap-anywhere">{value || "—"}</dd>
    </div>
  )
}

export function TargetProbePage({ workspace }: { workspace: Workspace }) {
  const { state, busy, pending, run, pick } = workspace
  const [urlPattern, setUrlPattern] = useState("http://192-168-1-?.awd.example-ctf.com/")
  const [start, setStart] = useState("0")
  const [end, setEnd] = useState("255")
  const [outputDraft, setOutputDraft] = useState<string | null>(null)
  const [revision, setRevision] = useState(0)
  const outputFile = outputDraft ?? state?.attacker.outputFile ?? ""
  const activeCount = state?.attacker.activeCount ?? 0
  const running = state?.job?.startsWith("attack-") ? state.job : null
  const locked = busy || pending
  const { items, error, loading } = useUrls("active", null, activeCount * 1000 + revision)

  async function browseTargets() {
    const selectedPath = await pick("file")
    if (selectedPath) setOutputDraft(selectedPath)
  }

  return (
    <>
      <PageHeading title="目标探活" description="批量探测 AWD 站点，并管理攻击辅助使用的存活目标列表。"
        actions={<AttackStatus workspace={workspace} />} />

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(18rem,2fr)]">
        <Panel title="快速探活" description="URL 模板中的 ? 会替换为编号，编号范围包含起止值。">
          <form className="grid gap-4" onSubmit={(event) => {
            event.preventDefault()
            void run("attack-scan", {
              urlPattern, start: Number(start), end: Number(end), outputFile,
            })
          }}>
            <Field label="URL 模板" hint="必须包含 ? 作为编号占位符。">
              {(id) => <Input id={id} required spellCheck={false} value={urlPattern}
                onChange={(event) => setUrlPattern(event.target.value)} disabled={locked} />}
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="起始编号">
                {(id) => <Input id={id} type="number" required min={0} max={65535} value={start}
                  onChange={(event) => setStart(event.target.value)} disabled={locked} />}
              </Field>
              <Field label="结束编号">
                {(id) => <Input id={id} type="number" required min={0} max={65535} value={end}
                  onChange={(event) => setEnd(event.target.value)} disabled={locked} />}
              </Field>
            </div>
            <Field label="存活文件" hint="探活完成后覆盖写入 UTF-8 文本，每行一个 URL。">
              {(id) => <PathInput id={id} value={outputFile} onChange={setOutputDraft}
                pick={() => void browseTargets()} disabled={locked} />}
            </Field>
            <div>
              <Button type="submit" disabled={!state || locked || !urlPattern.trim() || !outputFile.trim()}>
                {running === "attack-scan" ? <Busy label="探活中" /> : <><Search />快速探活并写入</>}
              </Button>
            </div>
          </form>
        </Panel>

        <Panel title="载入目标列表" description="直接读取已有的存活文件，供攻击辅助检测后门。">
          <div className="grid gap-4">
            <Field label="目标文件" hint="忽略空行和以 # 开头的注释，并自动去重。">
              {(id) => <PathInput id={id} value={outputFile} onChange={setOutputDraft}
                pick={() => void browseTargets()} disabled={locked} />}
            </Field>
            <div>
              <Button type="button" variant="outline" disabled={!state || locked || !outputFile.trim()}
                onClick={() => void run("attack-read", { outputFile })}>
                {running === "attack-read" ? <Busy label="读取中" /> : <><FileInput />从文件读入</>}
              </Button>
            </div>
            <div className="rounded-md border bg-muted px-4 py-3">
              <p className="text-sm font-medium">当前存活目标</p>
              <p className="mt-1 text-2xl font-semibold tabular-nums">{activeCount}</p>
              <p className="mt-1 text-xs wrap-anywhere text-muted-foreground">{outputFile || "等待工作台提供默认文件路径"}</p>
            </div>
          </div>
        </Panel>
      </div>

      <Panel title="存活站点" description="探活或读入后写入的目标，攻击辅助会在这些站点上操作。"
        actions={<>
          <Badge variant="secondary" className="tabular-nums">{items.length} 条</Badge>
          <Button size="sm" variant="outline" disabled={loading}
            onClick={() => setRevision((value) => value + 1)}>
            {loading ? <Busy label="读取中" /> : <><RefreshCw />刷新列表</>}
          </Button>
        </>}>
        <div className="grid gap-3">
          {error && <Message>{error}</Message>}
          <UrlTable title="存活站点" items={items} empty="还没有存活目标，先执行一次探活或从文件读入。" />
        </div>
      </Panel>

      <LogPanel title="目标探活日志" area="attack" events={state?.events ?? []} />
    </>
  )
}

export function AttackerPage({ workspace }: { workspace: Workspace }) {
  const { state, busy, pending, run } = workspace
  const [path, setPath] = useState("public/img/1.php")
  const [keyMethod, setKeyMethod] = useState("0")
  const [keyName, setKeyName] = useState("")
  const [keyValue, setKeyValue] = useState("")
  const [cmdMethod, setCmdMethod] = useState("POST")
  const [payload, setPayload] = useState("cmd")
  const [shellNumber, setShellNumber] = useState("")
  const [command, setCommand] = useState("system('id');")
  const [remoteDir, setRemoteDir] = useState("/var/www/html/")
  const [urlDir, setUrlDir] = useState("/")
  const [withKey, setWithKey] = useState(true)
  const attack = state?.attacker
  const shells = attack?.shells ?? []
  const selected = shells.find((shell) => String(shell.number) === shellNumber)
  const running = state?.job?.startsWith("attack-") ? state.job : null
  const locked = busy || pending
  const sites = useUrls("shell", selected ? selected.number : null, shells.length)

  useEffect(() => {
    if (!shells.length) {
      setShellNumber("")
      return
    }
    if (!shells.some((shell) => String(shell.number) === shellNumber)) {
      setShellNumber(String(shells[0].number))
    }
  }, [shells, shellNumber])

  return (
    <>
      <PageHeading title="攻击辅助" description="检测已知后门，批量执行命令，并生成新的隐藏后门。"
        actions={<AttackStatus workspace={workspace} />} />

      <div className="grid items-start gap-4 xl:grid-cols-2">
        <Panel title="后门检测" description="在目标探活页面载入的存活站点中检查指定路径。">
          <form className="grid gap-4" onSubmit={(event) => {
            event.preventDefault()
            void run("attack-check", {
              path, keyMethod, key: keyName, keyValue, cmdMethod, payload,
            })
          }}>
            <Field label="后门路径">
              {(id) => <Input id={id} required spellCheck={false} value={path}
                onChange={(event) => setPath(event.target.value)} disabled={locked} />}
            </Field>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="key 方式">
                {(id) => <NativeSelect id={id} value={keyMethod} disabled={locked}
                  onChange={(event) => setKeyMethod(event.target.value)}>
                  <NativeSelectOption value="0">无</NativeSelectOption>
                  <NativeSelectOption value="GET">GET</NativeSelectOption>
                  <NativeSelectOption value="POST">POST</NativeSelectOption>
                </NativeSelect>}
              </Field>
              <Field label="命令方式">
                {(id) => <NativeSelect id={id} value={cmdMethod} disabled={locked}
                  onChange={(event) => setCmdMethod(event.target.value)}>
                  <NativeSelectOption value="GET">GET</NativeSelectOption>
                  <NativeSelectOption value="POST">POST</NativeSelectOption>
                </NativeSelect>}
              </Field>
              <Field label="key 参数名">
                {(id) => <Input id={id} spellCheck={false} value={keyName}
                  onChange={(event) => setKeyName(event.target.value)} disabled={locked || keyMethod === "0"} />}
              </Field>
              <Field label="key 值">
                {(id) => <Input id={id} spellCheck={false} value={keyValue}
                  onChange={(event) => setKeyValue(event.target.value)} disabled={locked || keyMethod === "0"} />}
              </Field>
            </div>
            <Field label="命令参数名">
              {(id) => <Input id={id} required spellCheck={false} value={payload}
                onChange={(event) => setPayload(event.target.value)} disabled={locked} />}
            </Field>
            <div>
              <Button type="submit" disabled={!state || locked || !attack?.activeCount || !path.trim() || !payload.trim()}>
                {running === "attack-check" ? <Busy label="检测中" /> : <><Crosshair />检测已知后门</>}
              </Button>
            </div>
          </form>
        </Panel>

        <Panel title="后门选择" description="选择本轮检测到或从本地配置自动加载的后门记录。"
          actions={selected && <Status>{selected.urlCount} 个站点</Status>}>
          <div className="grid gap-4">
            <Field label="后门记录"
              hint={shells.length ? "执行和上传操作会作用于这条记录中的全部站点。" : "请先载入目标并检测已知后门。"}>
              {(id) => <NativeSelect id={id} value={shellNumber} disabled={locked || !shells.length}
                onChange={(event) => setShellNumber(event.target.value)}>
                {!shells.length && <NativeSelectOption value="">暂无已知后门</NativeSelectOption>}
                {shells.map((shell) => <NativeSelectOption key={shell.number} value={shell.number}>
                  {shell.label}
                </NativeSelectOption>)}
              </NativeSelect>}
            </Field>
            {selected ? (
              <dl className="grid grid-cols-2 gap-3 rounded-md border bg-muted px-4 py-3">
                <Detail label="编号" value={String(selected.number)} />
                <Detail label="来源" value={selected.note} />
                <Detail label="命令参数名" value={selected.payload} />
                <Detail label="命令方式" value={selected.cmdMethod} />
                <Detail label="key 方式" value={selected.keyMethod === "0" ? "无" : selected.keyMethod} />
                <Detail label="key 参数名" value={selected.keyMethod === "0" ? "" : selected.key} />
                <Detail label="key 值" value={selected.keyMethod === "0" ? "" : selected.keyValue} />
                <Detail label="站点数" value={String(selected.urlCount)} />
              </dl>
            ) : (
              <Empty icon={<Crosshair />} title="还没有可用后门">检测到后门后即可在这里选择记录。</Empty>
            )}
          </div>
        </Panel>
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-2">
        <Panel title="执行命令" description="通过所选后门向记录中的站点批量提交命令。">
          <div className="grid gap-4">
            <Field label="执行内容" hint="eval 后门填写 PHP 代码；system 后门直接填写系统命令。">
              {(id) => <Textarea id={id} required spellCheck={false} value={command}
                onChange={(event) => setCommand(event.target.value)} disabled={locked}
                className="min-h-32 resize-y font-mono" />}
            </Field>
            <div>
              <Button disabled={!selected || locked || !command.trim()}
                onClick={() => void run("attack-exec", { shellNumber: selected?.number, command })}>
                {running === "attack-exec" ? <Busy label="执行中" /> : <><Play />执行命令</>}
              </Button>
            </div>
          </div>
        </Panel>

        <Panel title="生成新后门" description="通过所选后门在目标站点写入新的随机 PHP 后门。">
          <div className="grid gap-4">
            <Field label="写入目录" hint="服务器上的绝对目录，新文件会写到这里。">
              {(id) => <Input id={id} required spellCheck={false} value={remoteDir}
                onChange={(event) => setRemoteDir(event.target.value)} disabled={locked} />}
            </Field>
            <Field label="Web 访问目录" hint="写入目录对应的 URL 路径，用于生成新后门地址。">
              {(id) => <Input id={id} required spellCheck={false} value={urlDir}
                onChange={(event) => setUrlDir(event.target.value)} disabled={locked} />}
            </Field>
            <UiField orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="attack-with-key">生成带 key 后门</FieldLabel>
                <FieldDescription>启用后随机生成 key、key 值和命令参数，并保存到后门记录。</FieldDescription>
              </FieldContent>
              <Switch id="attack-with-key" checked={withKey} disabled={locked} onCheckedChange={setWithKey} />
            </UiField>
            <div>
              <Confirm title="生成并上传新后门" label="确认写入"
                description={`将通过后门 ${selected?.number ?? "-"} 在目标站点的 ${remoteDir || "-"} 写入新的 PHP 后门。`}
                disabled={!selected || locked || !remoteDir.trim() || !urlDir.trim()}
                onConfirm={() => void run("attack-upload", {
                  shellNumber: selected?.number, remoteDir, urlDir, withKey, confirmed: true,
                })}>
                {running === "attack-upload" ? <Busy label="上传中" /> : <><Upload />生成新后门并上传</>}
              </Confirm>
            </div>
          </div>
        </Panel>
      </div>

      <Panel title="本次操作的站点" description={selected ? `后门记录 ${selected.number} 中的全部站点。` : "选择后门记录后显示。"}
        actions={selected && <Badge variant="secondary" className="tabular-nums">{sites.items.length} 条</Badge>}>
        <div className="grid gap-3">
          {sites.error && <Message>{sites.error}</Message>}
          <UrlTable title="本次操作的站点" items={sites.items}
            empty={selected ? "这条记录还没有站点。" : "先在上方选择一条后门记录。"} />
        </div>
      </Panel>

      {!shells.length && <Panel title="开始使用" description="攻击操作已经就绪，完成以下两步后按钮会自动启用。">
        <div className="flex items-start gap-3 text-sm text-muted-foreground">
          <Radar className="mt-0.5 size-4 shrink-0" aria-hidden />
          <p>先在“目标探活”载入存活站点，再回到此页检测已知后门。执行命令和生成新后门会使用选中的后门记录。</p>
        </div>
      </Panel>}

      <LogPanel title="攻击辅助日志" area="attack" events={state?.events ?? []} />
    </>
  )
}
