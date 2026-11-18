import { useState, type ReactNode } from "react"
import { Archive, FileText, ShieldCheck, Upload } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Field as UiField, FieldContent, FieldDescription, FieldLabel } from "@/components/ui/field"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Switch } from "@/components/ui/switch"
import { Busy, Confirm, Field, LogPanel, PageHeading, Panel, PathInput, Status, type Workspace } from "@/components/workspace"
import { defaultWaf, type WafConfig } from "@/lib/desktop"

export function WafPage({ workspace }: { workspace: Workspace }) {
  const connection = workspace.state?.connection
  const key = connection ? JSON.stringify(connection) : "offline"
  return <WafSettings key={key} workspace={workspace} />
}

function WafSettings({ workspace: { state, busy, run, pending } }: { workspace: Workspace }) {
  const [draft, setDraft] = useState<Partial<WafConfig>>({})
  const waf = { ...defaultWaf, ...state?.waf, ...draft }
  const set = <K extends keyof WafConfig>(key: K, value: WafConfig[K]) => setDraft((old) => ({ ...old, [key]: value }))
  const connected = !!state?.connection
  const deployed = !!state?.waf.deployed
  const guard = !!state?.waf.guard
  const locked = deployed || busy
  const running = state?.job

  return (
    <>
      <PageHeading title="WAF 管理" description="部署项目内置的 PHP WAF，并管理守护与请求日志。"
        actions={<Status tone={deployed ? "good" : "neutral"}>{deployed ? "本次已部署" : "本次未部署"}</Status>} />
      <Panel title="部署配置">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="站点目录">{(id) => <PathInput id={id} value={waf.webRoot}
            onChange={(value) => set("webRoot", value)} disabled={locked} />}</Field>
          <Field label="安装目录">{(id) => <PathInput id={id} value={waf.installDir}
            onChange={(value) => set("installDir", value)} disabled={locked} />}</Field>
          <Field label="日志目录">{(id) => <PathInput id={id} value={waf.logDir}
            onChange={(value) => set("logDir", value)} disabled={locked} />}</Field>
          <Field label="跳转路由">{(id) => <PathInput id={id} value={waf.redirect}
            onChange={(value) => set("redirect", value)} disabled={locked || waf.mode !== 2} />}</Field>
          <Field label="拦截方式">{(id) => <NativeSelect id={id} value={waf.mode} disabled={locked}
            onChange={(event) => set("mode", Number(event.target.value))}>
            <NativeSelectOption value={1}>关键词替换</NativeSelectOption>
            <NativeSelectOption value={2}>跳转路由</NativeSelectOption>
          </NativeSelect>}</Field>
          <Field label="严格程度">{(id) => <NativeSelect id={id} value={waf.strict} disabled={locked}
            onChange={(event) => set("strict", Number(event.target.value))}>
            <NativeSelectOption value={1}>简单</NativeSelectOption>
            <NativeSelectOption value={2}>常见</NativeSelectOption>
            <NativeSelectOption value={3}>全量</NativeSelectOption>
          </NativeSelect>}</Field>
        </div>
        <UiField orientation="horizontal" className="my-4">
          <FieldContent>
            <FieldLabel htmlFor="waf-log-all">记录全部请求</FieldLabel>
            <FieldDescription>部署时开启后，也会记录未命中的 PHP 请求。</FieldDescription>
          </FieldContent>
          <Switch id="waf-log-all" checked={waf.logAll} disabled={locked} onCheckedChange={(value) => set("logAll", value)} />
        </UiField>
        <div className="flex flex-wrap items-center gap-2">
          <Confirm title="部署 WAF" label="确认部署" disabled={!connected || busy || deployed}
            description={`将在 ${state?.connection?.host} 的 ${waf.webRoot} 目录中写入 WAF 引用。`}
            onConfirm={() => void run("deploy-waf", { ...waf, confirmed: true })}>
            {running === "deploy-waf" ? <Busy label="部署中" /> : <><ShieldCheck />部署 WAF</>}
          </Confirm>
          <Button variant="outline" disabled={!connected || !deployed || pending || (!guard && busy)}
            onClick={() => void run(guard ? "stop-guard" : "start-guard")}>
            {guard ? "停止守护" : "启动守护"}
          </Button>
          <Confirm title="更新 WAF 日志模板" label="更新模板" disabled={!connected || busy}
            description={`将 ${state?.connection?.host} 上的 ${waf.installDir}/waf.php 备份到本机，再安装新版采集模板。`}
            onConfirm={() => void run("update-waf-capture", { installDir: waf.installDir, confirmed: true })}>
            {running === "update-waf-capture" ? <Busy label="更新中" /> : <><FileText />更新日志模板</>}
          </Confirm>
          <Confirm title="卸载 WAF" label="确认卸载" disabled={!connected || busy}
            description={`将在 ${state?.connection?.host} 的 ${waf.webRoot} 移除来自 ${waf.installDir} 的 WAF 引用。`}
            onConfirm={() => void run("remove-waf", { ...waf, confirmed: true })}>
            {running === "remove-waf" ? <Busy label="卸载中" /> : "卸载 WAF"}
          </Confirm>
          {!connected && <small className="text-muted-foreground">请先验证 SSH 连接。</small>}
          {guard && <Status tone="good">守护运行中</Status>}
        </div>
      </Panel>
      <LogPanel title="WAF 日志" area="waf" events={state?.events ?? []} />
    </>
  )
}

export function BackupPage({ workspace: { state, busy, run, pick } }: { workspace: Workspace }) {
  const [webRoot, setWebRoot] = useState("/var/www/html/")
  const [destinationDraft, setDestinationDraft] = useState<string | null>(null)
  const [archive, setArchive] = useState("")
  const destination = destinationDraft ?? state?.backupDir ?? ""
  const disabled = !state?.connection || busy
  const browse = async (kind: "directory" | "archive", choose: (value: string) => void) => {
    const value = await pick(kind)
    if (value) choose(value)
  }
  const headingAction: ReactNode = !state?.connection ? <Status>等待 SSH</Status> : null

  return (
    <>
      <PageHeading title="源码备份" description="从服务器打包站点目录，或从本地备份恢复。"
        actions={headingAction} />
      <Panel title="站点目录">
        <Field label="服务器路径">{(id) => <PathInput id={id} value={webRoot} onChange={setWebRoot} />}</Field>
      </Panel>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="下载备份" description="将站点源码保存到本机。">
          <form className="grid gap-4" onSubmit={(event) => {
            event.preventDefault()
            void run("backup", { webRoot, destination })
          }}>
            <Field label="下载目录">{(id) => <PathInput id={id} value={destination}
              onChange={setDestinationDraft} pick={() => void browse("directory", setDestinationDraft)} />}</Field>
            <div><Button type="submit" disabled={disabled}>
              {state?.job === "backup" ? <Busy label="打包中" /> : <><Archive />打包并下载</>}
            </Button></div>
          </form>
        </Panel>
        <Panel title="恢复备份" description="选择已有的 .tar.gz 或 .tgz 文件。">
          <div className="grid gap-4">
            <Field label="备份文件">{(id) => <PathInput id={id} value={archive} onChange={setArchive}
              pick={() => void browse("archive", setArchive)} />}</Field>
            <div><Confirm title="从备份恢复站点" description={`将备份并替换 ${state?.connection?.host} 的 ${webRoot} 目录中的文件。`}
              label="确认恢复" disabled={disabled || !archive.trim()}
              onConfirm={() => void run("restore", { webRoot, archive, confirmed: true })}>
              {state?.job === "restore" ? <Busy label="恢复中" /> : <><Upload />恢复到站点</>}
            </Confirm></div>
          </div>
        </Panel>
      </div>
      <LogPanel title="备份日志" area="backup" events={state?.events ?? []} />
    </>
  )
}
