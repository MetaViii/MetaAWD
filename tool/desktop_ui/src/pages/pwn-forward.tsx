import { useState } from "react"
import {
  ClipboardCopy, Download, FileArchive, Network, RadioTower, Route, ShieldBan, TerminalSquare,
} from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Busy, Empty, Field, Message, PageHeading, Panel, Status, type Workspace } from "@/components/workspace"
import {
  callDesktop, errorText, type PwnForwardMode, type PwnForwardOptions, type PwnForwardPlan,
} from "@/lib/desktop"

const defaults: PwnForwardOptions = {
  mode: "catch",
  architecture: 64,
  logEnabled: true,
  logPath: "/tmp/.metaawd-pwn",
  logPermissions: "0770",
  compiler: "gcc",
  optimization: "2",
  staticLink: true,
  stripBinary: true,
  extraWarnings: true,
  serviceName: "metaawd-pwn",
  servicePath: "/pwn",
  backupPath: "/opt/metaawd-backup/pwn.original",
  serviceUser: "pwn",
  serviceGroup: "pwn",
  listenAddress: "0.0.0.0",
  listenPort: 10000,
  perSource: 10,
  instances: 128,
  cpuLimit: 20,
  memoryLimitMb: 256,
  forwardHost: "127.0.0.1",
  forwardPort: 20000,
  targets: "127.0.0.1:20000\n127.0.0.1:20001",
  installXinetd: true,
  restartMethod: "systemctl",
}

const modes: { value: PwnForwardMode; label: string; summary: string; icon: typeof RadioTower }[] = [
  { value: "catch", label: "CATCH", summary: "运行原程序，完整记录标准输入输出和危险系统调用。", icon: RadioTower },
  { value: "i0gan", label: "I0GAN", summary: "记录交互，并在后续危险系统调用出现时终止本次处理。", icon: ShieldBan },
  { value: "forward", label: "FORWARD", summary: "把每个连接的标准输入输出转发到一个固定 IPv4 目标。", icon: Route },
  { value: "forward_multi", label: "FORWARD_MULTI", summary: "按新连接轮询 hosts.txt 中的多个 IPv4 目标。", icon: Network },
]

function NumberField({ label, hint, value, minimum, maximum, disabled, onChange }: {
  label: string
  hint?: string
  value: number | null
  minimum: number
  maximum: number
  disabled?: boolean
  onChange: (value: number | null) => void
}) {
  return <Field label={label} hint={hint}>{(id) => <Input id={id} type="number" required min={minimum} max={maximum}
    value={value ?? ""} disabled={disabled} onChange={(event) => onChange(event.target.value === "" ? null : Number(event.target.value))} />}</Field>
}

function PlanPreview({ plan, copy }: { plan: PwnForwardPlan; copy: (text: string, label: string) => void }) {
  return (
    <div className="grid gap-5">
      <div className="flex flex-wrap items-center gap-2">
        <Status>{plan.modeLabel}</Status>
        <Badge variant="outline" className="rounded-md font-mono">{plan.binary}</Badge>
        {plan.targetCount > 0 && <Badge variant="secondary">{plan.targetCount} 个目标</Badge>}
      </div>
      <p className="text-sm leading-relaxed text-muted-foreground">{plan.description}</p>
      <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2 xl:grid-cols-3">
        {plan.summary.map((item) => <div key={item.label} className="min-w-0">
          <dt className="text-xs text-muted-foreground">{item.label}</dt>
          <dd className="mt-1 wrap-anywhere font-medium">{item.value}</dd>
        </div>)}
      </dl>
      <Separator />
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="构建命令">{(id) => <div className="flex gap-2">
          <Input id={id} readOnly value={plan.buildCommand} className="font-mono text-xs" />
          <Button type="button" variant="outline" size="icon" title="复制构建命令" aria-label="复制构建命令"
            onClick={() => copy(plan.buildCommand, "构建命令")}><ClipboardCopy /></Button>
        </div>}</Field>
        <Field label="部署命令">{(id) => <div className="flex gap-2">
          <Input id={id} readOnly value={plan.deployCommand} className="font-mono text-xs" />
          <Button type="button" variant="outline" size="icon" title="复制部署命令" aria-label="复制部署命令"
            onClick={() => copy(plan.deployCommand, "部署命令")}><ClipboardCopy /></Button>
        </div>}</Field>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Field label="xinetd 配置">{(id) => <Textarea id={id} readOnly value={plan.xinetd}
          className="min-h-64 font-mono text-xs" />}</Field>
        <Field label="Makefile">{(id) => <Textarea id={id} readOnly value={plan.makefile}
          className="min-h-64 font-mono text-xs" />}</Field>
      </div>
      <div>
        <p className="mb-2 text-sm font-medium">导出文件</p>
        <div className="flex flex-wrap gap-1.5">
          {plan.files.map((file) => <Badge key={file} variant="secondary" className="rounded-md font-mono font-normal">
            {file}
          </Badge>)}
        </div>
      </div>
      <Alert><TerminalSquare /><AlertTitle>部署前检查</AlertTitle><AlertDescription>
        <ul className="list-disc space-y-1 pl-4">{plan.notes.map((note) => <li key={note}>{note}</li>)}</ul>
      </AlertDescription></Alert>
    </div>
  )
}

export function PwnForwardPage({ workspace }: { workspace: Workspace }) {
  const [options, setOptions] = useState(defaults)
  const [plan, setPlan] = useState<PwnForwardPlan | null>(null)
  const [pending, setPending] = useState(false)
  const [saving, setSaving] = useState(false)
  const [issue, setIssue] = useState("")
  const [feedback, setFeedback] = useState("")
  const selectedMode = modes.find((mode) => mode.value === options.mode) ?? modes[0]
  const ModeIcon = selectedMode.icon

  function update<K extends keyof PwnForwardOptions>(key: K, value: PwnForwardOptions[K]) {
    setOptions((previous) => ({ ...previous, [key]: value }))
    setPlan(null)
    setIssue("")
    setFeedback("")
  }

  async function preview() {
    setPending(true)
    setIssue("")
    setFeedback("")
    try { setPlan(await callDesktop("pwn_forward_plan", options)) }
    catch (error) { setIssue(errorText(error)) }
    finally { setPending(false) }
  }

  async function save() {
    setSaving(true)
    setIssue("")
    try {
      const output = await callDesktop("export_pwn_forward", options)
      if (output) {
        setPlan(output)
        setFeedback(`构建包已导出至 ${output.directory}`)
      }
    } catch (error) { setIssue(errorText(error)) }
    finally { setSaving(false) }
  }

  async function copy(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text)
      setFeedback(`已复制${label}`)
    } catch { setIssue("复制失败，可直接选中对应内容。") }
  }

  const disabled = pending || saving
  return (
    <>
      <PageHeading title="PWN 流量转发" description="配置 CATCH、I0GAN、FORWARD 与 FORWARD_MULTI，导出 Linux 构建、xinetd 部署和回滚文件。"
        actions={<Button onClick={() => void save()} disabled={!plan || disabled}>
          {saving ? <Busy label="导出中" /> : <><Download />导出构建包</>}
        </Button>} />

      <Panel title="运行模式" description="模式与参数兼容 i0gan/pwn_waf；导出包会同时保留四个 Makefile 构建目标。">
        <Tabs value={options.mode} onValueChange={(value) => update("mode", value as PwnForwardMode)}>
          <TabsList className="grid h-auto w-full grid-cols-1 gap-1 min-[420px]:grid-cols-2 sm:grid-cols-4">
            {modes.map(({ value, label, icon: Icon }) => <TabsTrigger key={value} value={value} disabled={disabled} className="h-9 min-w-0">
              <Icon /><span className="truncate">{label}</span>
            </TabsTrigger>)}
          </TabsList>
        </Tabs>
        <Alert className="mt-4"><ModeIcon /><AlertTitle>{selectedMode.label}</AlertTitle>
          <AlertDescription>{selectedMode.summary}</AlertDescription></Alert>
      </Panel>

      <form className="grid gap-4" onSubmit={(event) => { event.preventDefault(); void preview() }}>
        <fieldset disabled={disabled} className="grid items-start gap-4 xl:grid-cols-2">
          <Panel title="运行与转发" description="设置服务程序位置、原程序备份以及转发目标。">
            <div className="grid gap-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="服务程序路径" hint="部署时由所选模式二进制替换，原文件会先备份。">
                  {(id) => <Input id={id} value={options.servicePath} spellCheck={false}
                    onChange={(event) => update("servicePath", event.target.value)} />}
                </Field>
                <Field label="原程序备份路径" hint="root 管理的可信副本；CATCH / I0GAN 直接从此路径启动，回滚也从这里恢复。">
                  {(id) => <Input id={id} value={options.backupPath} spellCheck={false}
                    onChange={(event) => update("backupPath", event.target.value)} />}
                </Field>
              </div>
              {options.mode === "forward" && <div className="grid gap-4 sm:grid-cols-[minmax(0,2fr)_minmax(8rem,1fr)]">
                <Field label="单目标 IPv4" hint="每个进入服务的连接都转发到该地址。">
                  {(id) => <Input id={id} value={options.forwardHost} placeholder="127.0.0.1" spellCheck={false}
                    onChange={(event) => update("forwardHost", event.target.value)} />}
                </Field>
                <NumberField label="目标端口" value={options.forwardPort} minimum={1} maximum={65535}
                  onChange={(value) => update("forwardPort", value)} />
              </div>}
              {options.mode === "forward_multi" && <Field label="多目标列表"
                hint="每行一个 IPv4:端口；忽略空行、# 注释和重复项，最多 256 个。">
                {(id) => <Textarea id={id} value={options.targets} className="min-h-36 font-mono text-xs"
                  placeholder="127.0.0.1:20000" spellCheck={false}
                  onChange={(event) => update("targets", event.target.value)} />}
              </Field>}
              {(options.mode === "catch" || options.mode === "i0gan") && <Alert>
                <RadioTower /><AlertTitle>root 管理的原程序</AlertTitle><AlertDescription>
                  部署脚本会把原程序及 UID、GID、权限元数据保存到可信备份路径。包装程序从该只读副本启动，日志目录只存运行日志。
                </AlertDescription>
              </Alert>}
            </div>
          </Panel>

          <Panel title="xinetd 服务" description="生成独立 TCP 服务配置，并限制连接数与进程资源。">
            <div className="grid gap-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="服务名">{(id) => <Input id={id} value={options.serviceName}
                  onChange={(event) => update("serviceName", event.target.value)} />}</Field>
                <Field label="监听 IPv4">{(id) => <Input id={id} value={options.listenAddress} spellCheck={false}
                  onChange={(event) => update("listenAddress", event.target.value)} />}</Field>
                <Field label="服务用户">{(id) => <Input id={id} value={options.serviceUser}
                  onChange={(event) => update("serviceUser", event.target.value)} />}</Field>
                <Field label="服务用户组">{(id) => <Input id={id} value={options.serviceGroup}
                  onChange={(event) => update("serviceGroup", event.target.value)} />}</Field>
              </div>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <NumberField label="监听端口" value={options.listenPort} minimum={1} maximum={65535}
                  onChange={(value) => update("listenPort", value)} />
                <NumberField label="单来源并发" value={options.perSource} minimum={1} maximum={1024}
                  onChange={(value) => update("perSource", value)} />
                <NumberField label="总实例上限" value={options.instances} minimum={1} maximum={4096}
                  onChange={(value) => update("instances", value)} />
                <NumberField label="CPU 秒数" value={options.cpuLimit} minimum={1} maximum={3600}
                  onChange={(value) => update("cpuLimit", value)} />
                <NumberField label="内存限制 MiB" value={options.memoryLimitMb} minimum={16} maximum={65536}
                  onChange={(value) => update("memoryLimitMb", value)} />
              </div>
              <Separator />
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="安装 xinetd 配置" hint="部署脚本写入 /etc/xinetd.d/ 并保留旧配置。">
                  {(id) => <Switch id={id} checked={options.installXinetd}
                    onCheckedChange={(checked) => update("installXinetd", checked)} />}
                </Field>
                <Field label="重新加载方式">
                  {(id) => <NativeSelect id={id} value={options.restartMethod} disabled={!options.installXinetd}
                    onChange={(event) => update("restartMethod", event.target.value as PwnForwardOptions["restartMethod"])}>
                    <NativeSelectOption value="systemctl">systemctl restart xinetd</NativeSelectOption>
                    <NativeSelectOption value="service">service xinetd restart</NativeSelectOption>
                    <NativeSelectOption value="none">仅写配置，不自动重启</NativeSelectOption>
                  </NativeSelect>}
                </Field>
              </div>
            </div>
          </Panel>

          <Panel title="构建与日志" description="参数写入 Makefile；实际编译在目标兼容的 Linux 环境完成。" className="xl:col-span-2">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <Field label="目标 x86 架构">
                {(id) => <NativeSelect id={id} value={String(options.architecture)}
                  onChange={(event) => update("architecture", Number(event.target.value) as 32 | 64)}>
                  <NativeSelectOption value="64">x86-64（64 位）</NativeSelectOption>
                  <NativeSelectOption value="32">x86（32 位，添加 -m32）</NativeSelectOption>
                </NativeSelect>}
              </Field>
              <Field label="编译器">
                {(id) => <NativeSelect id={id} value={options.compiler}
                  onChange={(event) => update("compiler", event.target.value as PwnForwardOptions["compiler"])}>
                  <NativeSelectOption value="gcc">gcc</NativeSelectOption>
                  <NativeSelectOption value="musl-gcc">musl-gcc</NativeSelectOption>
                </NativeSelect>}
              </Field>
              <Field label="优化级别">
                {(id) => <NativeSelect id={id} value={options.optimization}
                  onChange={(event) => update("optimization", event.target.value as PwnForwardOptions["optimization"])}>
                  <NativeSelectOption value="0">O0 · 便于调试</NativeSelectOption>
                  <NativeSelectOption value="1">O1</NativeSelectOption>
                  <NativeSelectOption value="2">O2 · 推荐</NativeSelectOption>
                  <NativeSelectOption value="3">O3</NativeSelectOption>
                  <NativeSelectOption value="s">Os · 优先体积</NativeSelectOption>
                </NativeSelect>}
              </Field>
              <Field label="日志目录权限">
                {(id) => <NativeSelect id={id} value={options.logPermissions}
                  onChange={(event) => update("logPermissions", event.target.value as PwnForwardOptions["logPermissions"])}>
                  <NativeSelectOption value="0750">0750 · 用户可写</NativeSelectOption>
                  <NativeSelectOption value="0770">0770 · 用户组可写</NativeSelectOption>
                  <NativeSelectOption value="0777">0777 · 全部可写</NativeSelectOption>
                </NativeSelect>}
              </Field>
              <Field label="运行数据目录" hint="仅保存交互日志和多目标轮询状态；已有目录只校验属主与写权限。">
                {(id) => <Input id={id} value={options.logPath} spellCheck={false}
                  onChange={(event) => update("logPath", event.target.value)} />}
              </Field>
              <Field label="记录流量日志" hint="保留原始字节；同一方向的十六进制预览最多缓存 1 MiB，超出会标记截断。">
                {(id) => <Switch id={id} checked={options.logEnabled}
                  onCheckedChange={(checked) => update("logEnabled", checked)} />}
              </Field>
              <Field label="静态链接" hint="需要编译环境安装对应静态库。">
                {(id) => <Switch id={id} checked={options.staticLink}
                  onCheckedChange={(checked) => update("staticLink", checked)} />}
              </Field>
              <Field label="移除符号">
                {(id) => <Switch id={id} checked={options.stripBinary}
                  onCheckedChange={(checked) => update("stripBinary", checked)} />}
              </Field>
              <Field label="额外编译警告" hint="添加 -Wall -Wextra。">
                {(id) => <Switch id={id} checked={options.extraWarnings}
                  onCheckedChange={(checked) => update("extraWarnings", checked)} />}
              </Field>
            </div>
          </Panel>
        </fieldset>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={!workspace.state || disabled}>
            {pending ? <Busy label="校验中" /> : <><FileArchive />生成构建预览</>}
          </Button>
          {feedback && <p role="status" className="wrap-anywhere text-sm text-muted-foreground">{feedback}</p>}
        </div>
      </form>

      {issue && <Message>{issue}</Message>}
      <Panel title="构建包预览" description="确认命令、xinetd 配置和文件清单后再导出。" className="min-w-0">
        {plan ? <PlanPreview plan={plan} copy={(text, label) => void copy(text, label)} />
          : <Empty icon={<FileArchive />} title={pending ? "正在校验参数" : "等待生成预览"}>
            <p>预览通过后可选择本地目录，导出完整 Linux 构建包。</p>
          </Empty>}
      </Panel>
    </>
  )
}
