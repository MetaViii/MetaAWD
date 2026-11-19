import { useState } from "react"
import { ClipboardCopy, Download, FileSearch, Shield, ShieldCheck } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Busy, Empty, Field, Message, PageHeading, Panel, PathInput, Status, type Workspace } from "@/components/workspace"
import { callDesktop, errorText, type ElfAudit, type PwnOptions, type PwnPolicy } from "@/lib/desktop"
import { PwnBundleTab } from "@/pages/pwn-bundle"

const defaults: PwnOptions = {
  unit: "", syscalls: "baseline", filesystem: "inherit", network: "inherit",
  writablePaths: "", inaccessiblePaths: "", noNewPrivileges: true, privateTmp: false,
  nativeAbi: false, denyWritableExecute: false, noExecTemp: false,
}
const toggles = [
  { key: "noNewPrivileges", label: "禁止获取新权限", hint: "防止后续执行提升权限。" },
  { key: "privateTmp", label: "隔离临时目录", hint: "使用独立的 /tmp 和 /var/tmp。" },
  { key: "nativeAbi", label: "仅允许原生 ABI", hint: "使用兼容 ABI 的服务需验证。" },
  { key: "denyWritableExecute", label: "限制可执行内存", hint: "使用 JIT 的服务需验证。" },
  { key: "noExecTemp", label: "限制临时目录中的程序执行", hint: "覆盖 /tmp、/var/tmp 和 /dev/shm。" },
] as const

function ElfResult({ audit }: { audit: ElfAudit }) {
  const status = { on: "已启用", off: "未启用", unknown: "未判定" }
  const relro = { full: "完整", partial: "部分", off: "未发现", present: "有保护段（无动态段）" }
  const rows = [
    ["NX 栈", status[audit.nx], "查看 PT_GNU_STACK 是否要求可执行栈。"],
    ["PIE", status[audit.pie], "根据 ELF 类型、加载器信息与动态标记判定。"],
    ["RELRO", relro[audit.relro], "检查 GNU_RELRO 段和动态链接的立即绑定标志。"],
    ["栈保护 Canary", audit.canary ? "发现符号" : "未发现符号", "检查可见的栈保护失败处理符号。"],
    ["FORTIFY", audit.fortify ? "发现符号" : "未发现符号", "检查可见的受检库函数符号。"],
  ]
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap gap-2">
        <Status>{audit.bits} 位 · {audit.endian === "little" ? "小端" : "大端"}</Status>
        <Status>{audit.machine}</Status><Status>{audit.kind}</Status>
        <Status>{audit.dynamic ? "有动态段" : "无动态段"}</Status>
      </div>
      <dl className="grid gap-2 text-sm">
        <div><dt className="text-muted-foreground">文件</dt><dd className="wrap-anywhere">{audit.path}</dd></div>
        <div><dt className="text-muted-foreground">大小</dt><dd>{audit.size.toLocaleString()} 字节</dd></div>
        <div><dt className="text-muted-foreground">SHA-256</dt><dd className="wrap-anywhere font-mono text-xs">{audit.sha256}</dd></div>
      </dl>
      <Table aria-label="ELF 加固项">
        <TableHeader><TableRow><TableHead>检查项</TableHead><TableHead>结果</TableHead><TableHead>依据</TableHead></TableRow></TableHeader>
        <TableBody>{rows.map(([name, value, reason]) => (
          <TableRow key={name}><TableCell>{name}</TableCell><TableCell><Status>{value}</Status></TableCell>
            <TableCell className="whitespace-normal">{reason}</TableCell></TableRow>
        ))}</TableBody>
      </Table>
      <p className="text-sm text-muted-foreground">静态链接和符号剥离会影响符号检查。结合构建参数确认覆盖范围。</p>
    </div>
  )
}

function AuditTab({ workspace }: { workspace: Workspace }) {
  const [path, setPath] = useState("")
  const [audit, setAudit] = useState<ElfAudit | null>(null)
  const [issue, setIssue] = useState("")
  const [pending, setPending] = useState(false)

  function changePath(value: string) {
    setPath(value)
    setAudit(null)
    setIssue("")
  }

  async function inspect() {
    setPending(true)
    setIssue("")
    setAudit(null)
    try { setAudit(await callDesktop("pwn_audit", path.trim())) }
    catch (error) { setIssue(errorText(error)) }
    finally { setPending(false) }
  }

  return (
    <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
      <Panel title="本地 ELF" description="只读检查 ELF 文件的加固标记和可见符号。">
        <form className="grid gap-4" onSubmit={(event) => { event.preventDefault(); void inspect() }}>
          <Field label="ELF 文件路径">
            {(id) => <PathInput id={id} value={path} disabled={pending} onChange={changePath} pick={async () => {
              const selected = await workspace.pick("file")
              if (selected) changePath(selected)
            }} />}
          </Field>
          <div><Button type="submit" disabled={!workspace.state || pending || !path.trim()}>
            {pending ? <Busy label="体检中" /> : <><FileSearch />开始体检</>}
          </Button></div>
          {issue && <Message>{issue}</Message>}
        </form>
      </Panel>
      <Panel title="体检结果" className="min-w-0">
        {audit ? <ElfResult audit={audit} /> : <Empty icon={<FileSearch />} title={pending ? "正在读取 ELF" : "等待体检"} />}
      </Panel>
    </div>
  )
}

function PolicyTab({ ready }: { ready: boolean }) {
  const [options, setOptions] = useState(defaults)
  const [plan, setPlan] = useState<PwnPolicy | null>(null)
  const [pending, setPending] = useState(false)
  const [saving, setSaving] = useState(false)
  const [issue, setIssue] = useState("")
  const [feedback, setFeedback] = useState("")

  function update<K extends keyof PwnOptions>(key: K, value: PwnOptions[K]) {
    setOptions((previous) => ({ ...previous, [key]: value }))
    setPlan(null)
    setIssue("")
    setFeedback("")
  }

  async function preview() {
    setIssue("")
    setFeedback("")
    setPending(true)
    try { setPlan(await callDesktop("pwn_plan", options)) }
    catch (error) { setIssue(errorText(error)) }
    finally { setPending(false) }
  }

  async function save() {
    setSaving(true)
    setIssue("")
    try {
      const path = await callDesktop("export_pwn_policy", options)
      if (path) setFeedback(`已保存至 ${path}`)
    } catch (error) { setIssue(errorText(error)) }
    finally { setSaving(false) }
  }

  return (
    <div className="grid items-start gap-4 xl:grid-cols-2">
      <Panel title="服务防护参数" description="生成 Linux systemd 服务的 drop-in 配置。">
        <form className="grid gap-4" onSubmit={(event) => { event.preventDefault(); void preview() }}>
          <fieldset disabled={pending || saving} className="grid gap-4">
            <Field label="服务单元">
              {(id) => <Input id={id} required value={options.unit} placeholder="example.service"
                onChange={(event) => update("unit", event.target.value)} />}
            </Field>
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label="系统调用策略">
                {(id) => <NativeSelect id={id} className="w-full" value={options.syscalls}
                  onChange={(event) => update("syscalls", event.target.value as PwnOptions["syscalls"])}>
                  <NativeSelectOption value="inherit">沿用服务配置</NativeSelectOption>
                  <NativeSelectOption value="baseline">限制高风险调用</NativeSelectOption>
                  <NativeSelectOption value="service">常规服务白名单</NativeSelectOption>
                </NativeSelect>}
              </Field>
              <Field label="文件系统">
                {(id) => <NativeSelect id={id} className="w-full" value={options.filesystem}
                  onChange={(event) => update("filesystem", event.target.value as PwnOptions["filesystem"])}>
                  <NativeSelectOption value="inherit">沿用服务配置</NativeSelectOption>
                  <NativeSelectOption value="full">系统目录只读</NativeSelectOption>
                  <NativeSelectOption value="strict">严格只读</NativeSelectOption>
                </NativeSelect>}
              </Field>
              <Field label="套接字地址族">
                {(id) => <NativeSelect id={id} className="w-full" value={options.network}
                  onChange={(event) => update("network", event.target.value as PwnOptions["network"])}>
                  <NativeSelectOption value="inherit">沿用服务配置</NativeSelectOption>
                  <NativeSelectOption value="unix">仅 Unix</NativeSelectOption>
                  <NativeSelectOption value="ip">Unix / IPv4 / IPv6</NativeSelectOption>
                </NativeSelect>}
              </Field>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="可写例外" hint="启用文件系统保护后，每行一个绝对路径。">
                {(id) => <Textarea id={id} value={options.writablePaths} placeholder="/var/lib/example"
                  spellCheck={false} onChange={(event) => update("writablePaths", event.target.value)} />}
              </Field>
              <Field label="隔离路径" hint="每行一个绝对路径，目标路径需存在。">
                {(id) => <Textarea id={id} value={options.inaccessiblePaths} placeholder="/srv/private"
                  spellCheck={false} onChange={(event) => update("inaccessiblePaths", event.target.value)} />}
              </Field>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              {toggles.map(({ key, label, hint }) => (
                <Field key={key} label={label} hint={hint}>
                  {(id) => <Switch id={id} checked={options[key]} onCheckedChange={(checked) => update(key, checked)} />}
                </Field>
              ))}
            </div>
          </fieldset>
          <div><Button type="submit" disabled={!ready || pending || saving || !options.unit.trim()}>
            {pending ? <Busy label="生成中" /> : <><ShieldCheck />生成策略预览</>}
          </Button></div>
        </form>
      </Panel>
      <Panel title="策略预览" className="min-w-0">
        {issue && <Message>{issue}</Message>}
        {plan ? <div className="grid gap-4">
          <Field label="Linux 目标路径">{(id) => <Input id={id} readOnly value={plan.target} className="font-mono text-xs" />}</Field>
          <Field label="配置内容">{(id) => <Textarea id={id} readOnly value={plan.text} className="min-h-40 font-mono text-xs" />}</Field>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" disabled={saving} onClick={() => void save()}><Download />导出 .conf</Button>
            <Button variant="outline" onClick={async () => {
              try {
                await navigator.clipboard.writeText(plan.text)
                setFeedback("已复制配置")
              } catch { setIssue("复制失败，可直接选中配置内容。") }
            }}><ClipboardCopy />复制配置</Button>
          </div>
          {feedback && <p role="status" className="wrap-anywhere text-sm text-muted-foreground">{feedback}</p>}
          <Table aria-label="策略解释">
            <TableHeader><TableRow><TableHead>生成项</TableHead><TableHead>影响</TableHead></TableRow></TableHeader>
            <TableBody>{plan.rules.map((rule) => (
              <TableRow key={rule.directive}>
                <TableCell className="whitespace-normal wrap-anywhere font-mono text-xs">{rule.directive}</TableCell>
                <TableCell className="whitespace-normal">{rule.effect}</TableCell>
              </TableRow>
            ))}</TableBody>
          </Table>
          <Alert><Shield /><AlertDescription>
            <ul className="list-disc space-y-1 pl-4">{plan.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
          </AlertDescription></Alert>
        </div> : <Empty icon={<Shield />} title="等待生成策略" />}
      </Panel>
    </div>
  )
}

export function PwnPage({ workspace }: { workspace: Workspace }) {
  return (
    <>
      <PageHeading title="PWN 沙箱防护" description="检查 ELF 加固状态，生成受限运行副本或 systemd 服务策略。" />
      <Tabs defaultValue="audit" className="gap-4">
        <TabsList>
          <TabsTrigger value="audit">ELF 体检</TabsTrigger>
          <TabsTrigger value="bundle">ELF 加固副本</TabsTrigger>
          <TabsTrigger value="policy">systemd 策略</TabsTrigger>
        </TabsList>
        <TabsContent value="audit" forceMount className="data-[state=inactive]:hidden">
          <AuditTab workspace={workspace} />
        </TabsContent>
        <TabsContent value="policy" forceMount className="data-[state=inactive]:hidden">
          <PolicyTab ready={!!workspace.state} />
        </TabsContent>
        <TabsContent value="bundle" forceMount className="data-[state=inactive]:hidden">
          <PwnBundleTab workspace={workspace} />
        </TabsContent>
      </Tabs>
    </>
  )
}
