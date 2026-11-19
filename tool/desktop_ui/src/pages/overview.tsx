import { Fragment } from "react"
import { ArrowRight, FileSearch, FolderClock, ScrollText, Server, ShieldCheck, type LucideIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemMedia, ItemSeparator, ItemTitle } from "@/components/ui/item"
import { Empty, PageHeading, Panel, Status, type Workspace } from "@/components/workspace"
import { monitorLabels } from "@/lib/desktop"

export type Page = "overview" | "ssh" | "terminal" | "monitor" | "scan" | "waf" | "pwn" | "pwnForward" | "packets" | "backup" | "activity" | "probe" | "attacker" | "bugku"

function Metric({ label, value, icon: Icon, detail }: {
  label: string; value: string | number; icon: LucideIcon; detail: string
}) {
  return (
    <CardContent className="min-w-0 bg-card px-4 py-4 sm:px-5">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-medium text-muted-foreground">{label}</p>
        <Badge variant="secondary" className="size-8 rounded-md bg-accent p-0 text-accent-foreground [&>svg]:size-4">
          <Icon aria-hidden />
        </Badge>
      </div>
      <p className="mt-1 text-2xl font-semibold tracking-tight tabular-nums">{value}</p>
      <p className="mt-1 truncate text-xs text-muted-foreground" title={detail}>{detail}</p>
    </CardContent>
  )
}

const quickLinks = [
  { page: "monitor", icon: FolderClock, label: "监控站点文件", detail: "建立基线并跟踪文件变更" },
  { page: "waf", icon: ShieldCheck, label: "配置 WAF", detail: "设置 PHP 请求拦截和记录方式" },
  { page: "packets", icon: ScrollText, label: "审查请求", detail: "查看 WAF 留存的请求日志" },
] as const

export function Overview({ workspace: { state }, go }: { workspace: Workspace; go: (page: Page) => void }) {
  const connection = state?.connection
  const monitor = state?.monitor
  const waf = state?.waf
  const scan = state?.scan

  return (
    <>
      <PageHeading title="防御概览" description="查看站点防护状态，或开始一次文件扫描。"
        actions={<><Button variant="outline" onClick={() => go("ssh")}><Server />配置 SSH</Button>
          <Button onClick={() => go("scan")}><FileSearch />打开查杀</Button></>} />
      <Card className="overflow-hidden py-0">
        <div className="grid gap-px bg-border sm:grid-cols-2 xl:grid-cols-4">
          <Metric label="SSH 连接" value={connection ? "已验证" : "未连接"} icon={Server}
            detail={connection ? `${connection.user}@${connection.host}` : "等待验证服务器"} />
          <Metric label="文件监控" value={monitorLabels[monitor?.state ?? "idle"]} icon={FolderClock}
            detail={monitor?.path || "等待建立监控基线"} />
          <Metric label="WAF 防护" value={waf?.deployed ? "已部署" : "未部署"} icon={ShieldCheck}
            detail={waf?.guard ? "守护运行中" : "本次会话部署状态"} />
          <Metric label="请求日志" value={state?.packetCount ?? "—"} icon={ScrollText}
            detail={state?.packetSync?.enabled ? "自动同步已开启" : "本地已同步的记录"} />
        </div>
      </Card>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Panel title="最近扫描"
          actions={scan && <Button size="sm" variant="ghost" onClick={() => go("scan")}>扫描详情 <ArrowRight /></Button>}>
          {scan?.status === "done" ? (
            <div className="grid gap-4">
              <div>
                <Status tone="good">扫描完成</Status>
                <p className="mt-2 text-sm wrap-anywhere text-muted-foreground" title={scan.target}>{scan.target}</p>
              </div>
              <dl className="grid grid-cols-3 gap-3">
                <div><dt className="text-xs text-muted-foreground">已扫描</dt><dd className="text-lg font-semibold">{scan.total}</dd></div>
                <div><dt className="text-xs text-muted-foreground">恶意</dt><dd className="text-lg font-semibold">{scan.malicious}</dd></div>
                <div><dt className="text-xs text-muted-foreground">可疑</dt><dd className="text-lg font-semibold">{scan.suspicious}</dd></div>
              </dl>
            </div>
          ) : (
            <Empty icon={<FileSearch />} title={scan?.status === "running" ? "扫描进行中"
              : scan?.status === "failed" ? "最近扫描失败" : "还没有扫描记录"}>
              <p>{scan ? "在查杀页查看进度与日志。" : "可扫描本地文件，也可通过 SSH 检查站点目录。"}</p>
            </Empty>
          )}
        </Panel>
        <Panel title="常用操作">
          <ItemGroup role="group">
            {quickLinks.map(({ page, icon: Icon, label, detail }, index) => (
              <Fragment key={page}>
                {index > 0 && <ItemSeparator />}
                <Item asChild size="sm" className="px-2.5 py-2.5">
                  <a href={`#${page}`} onClick={(event) => { event.preventDefault(); go(page) }}>
                    <ItemMedia variant="icon" className="border-transparent bg-accent text-accent-foreground">
                      <Icon aria-hidden />
                    </ItemMedia>
                    <ItemContent><ItemTitle>{label}</ItemTitle>
                      <ItemDescription className="text-xs">{detail}</ItemDescription></ItemContent>
                    <ItemActions><ArrowRight className="size-4 text-muted-foreground" aria-hidden /></ItemActions>
                  </a>
                </Item>
              </Fragment>
            ))}
          </ItemGroup>
        </Panel>
      </div>
      {state && (
        <Panel title="查杀规则"
          description={`默认判定阈值 ${state.scanDefaults.threshold}`}>
          <div className="flex flex-wrap gap-1.5">
            {state.scanDefaults.types.map((type) =>
              <Badge key={type} variant="secondary" className="rounded-md font-medium">{type.toUpperCase()}</Badge>)}
          </div>
        </Panel>
      )}
    </>
  )
}
