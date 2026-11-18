import { useEffect, useState } from "react"
import { Download, FileCheck, ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { Busy, Empty, Field, Message, Panel, PathInput, Status, type Workspace } from "@/components/workspace"
import { callDesktop, errorText, type ElfBundle, type ElfBundlePreset, type ElfBundleProfile } from "@/lib/desktop"

export function PwnBundleTab({ workspace }: { workspace: Workspace }) {
  const [path, setPath] = useState("")
  const [profiles, setProfiles] = useState<ElfBundleProfile[]>([])
  const [presets, setPresets] = useState<ElfBundlePreset[]>([])
  const [selected, setSelected] = useState<string[]>([])
  const [runnerReady, setRunnerReady] = useState(false)
  const [result, setResult] = useState<ElfBundle | null>(null)
  const [directory, setDirectory] = useState("")
  const [issue, setIssue] = useState("")
  const [pending, setPending] = useState<"preview" | "export" | null>(null)
  const ready = Boolean(workspace.state)
  const canInspect = ready && Boolean(path.trim()) && selected.length > 0 && !pending
  const preset = presets.find((item) => item.groups.length === selected.length
    && item.groups.every((group) => selected.includes(group)))

  useEffect(() => {
    if (!ready) return
    let ignore = false
    callDesktop("pwn_bundle_profiles").then((data) => {
      if (!ignore) {
        setProfiles(data.groups)
        setPresets(data.presets)
        setSelected(data.presets[0]?.groups ?? [])
        setRunnerReady(data.runnerReady)
      }
    }).catch((error) => {
      if (!ignore) setIssue(errorText(error))
    })
    return () => { ignore = true }
  }, [ready])

  function clearResult() {
    setResult(null)
    setDirectory("")
    setIssue("")
  }

  function changePath(value: string) {
    setPath(value)
    clearResult()
  }

  async function preview() {
    setIssue("")
    setPending("preview")
    try {
      setResult(await callDesktop("pwn_bundle_preview", path.trim(), selected))
    } catch (error) { setIssue(errorText(error)) }
    finally { setPending(null) }
  }

  async function save() {
    setIssue("")
    setPending("export")
    try {
      const output = await callDesktop("export_pwn_bundle", path.trim(), selected)
      if (output) {
        setResult(output)
        setDirectory(output.directory)
      }
    } catch (error) { setIssue(errorText(error)) }
    finally { setPending(null) }
  }

  return (
    <div className="grid items-start gap-4 xl:grid-cols-2">
      <Panel title="加固副本设置" description="适用于 Linux x86-64 可执行 ELF。">
        <div className="grid gap-4">
          <Field label="待加固 ELF">
            {(id) => <PathInput id={id} value={path} disabled={!!pending} onChange={changePath} pick={async () => {
              const file = await workspace.pick("file")
              if (file) changePath(file)
            }} />}
          </Field>
          {!!presets.length && <Field label="沙箱预设"
            hint={preset?.description ?? "已自定义规则。可选择预设重新套用对应的规则组。"}>
            {(id) => <NativeSelect id={id} value={preset?.id ?? "custom"} disabled={!!pending}
              className="w-full" onChange={(event) => {
                const choice = presets.find((item) => item.id === event.target.value)
                if (choice) {
                  setSelected(choice.groups)
                  clearResult()
                }
              }}>
              <NativeSelectOption value="custom" disabled>自定义</NativeSelectOption>
              {presets.map((item) => <NativeSelectOption key={item.id} value={item.id}>{item.label}</NativeSelectOption>)}
            </NativeSelect>}
          </Field>}
          {profiles.map((profile) => (
            <Field key={profile.id} label={profile.label} hint={profile.description}>
              {(id) => <Switch id={id} checked={selected.includes(profile.id)} disabled={!!pending}
                onCheckedChange={(checked) => {
                  setSelected((current) => checked ? [...current, profile.id] : current.filter((id) => id !== profile.id))
                  clearResult()
                }} />}
            </Field>
          ))}
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" disabled={!canInspect} onClick={() => void preview()}>
              {pending === "preview" ? <Busy label="校验中" /> : <><FileCheck />预览</>}
            </Button>
            <Button type="button" disabled={!canInspect || !runnerReady} onClick={() => void save()}>
              {pending === "export" ? <Busy label="导出中" /> : <><Download />生成加固副本</>}
            </Button>
          </div>
          {!!profiles.length && !runnerReady && <Message>缺少 Linux 启动器。请使用已打包版或按维护说明构建启动器。</Message>}
          {issue && <Message>{issue}</Message>}
        </div>
      </Panel>
      <Panel title="加固输出" className="min-w-0">
        {result ? <div className="grid gap-4">
          <div className="flex flex-wrap gap-2"><Status>Linux x86-64</Status><Status>拦截时返回 EPERM</Status></div>
          <dl className="grid gap-2 text-sm">
            <div><dt className="text-muted-foreground">原程序</dt><dd className="wrap-anywhere">{result.source}</dd></div>
            <div><dt className="text-muted-foreground">副本 SHA-256</dt><dd className="wrap-anywhere font-mono text-xs">{result.sha256}</dd></div>
            <div><dt className="text-muted-foreground">输出文件</dt><dd>{result.files.join("、")}</dd></div>
          </dl>
          <Field label="将拦截的系统调用">
            {(id) => <Textarea id={id} readOnly value={result.syscalls.join(", ")} className="font-mono text-xs" />}
          </Field>
          {directory && <p role="status" className="wrap-anywhere text-sm">已导出至 {directory}</p>}
          <p className="text-sm text-muted-foreground">
            把三个文件放在 Linux 同一目录，赋予 run-hardened 和 program.elf 执行权限，从 run-hardened 启动服务。
          </p>
        </div> : <Empty icon={<ShieldCheck />} title="等待预览或生成副本" />}
      </Panel>
    </div>
  )
}
