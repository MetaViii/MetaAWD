import { useEffect, useRef, useState, type CSSProperties } from "react"
import { createRoot } from "react-dom/client"
import {
  Activity, Archive, CircleCheck, Copy, Crosshair, FileSearch, Flag, FolderClock, LayoutDashboard, Minus, Moon,
  Network, ScrollText, Search, Server, Shield, ShieldAlert, ShieldCheck, ShieldEllipsis, Square, Sun, Terminal, Unplug,
  X, type LucideIcon,
} from "lucide-react"
import { Alert, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarGroupLabel,
  SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuButton, SidebarMenuItem,
  SidebarProvider, SidebarRail, SidebarSeparator, SidebarTrigger, useSidebar,
} from "@/components/ui/sidebar"
import { LogPanel, Message, PageHeading, useWorkspace } from "@/components/workspace"
import { AttackerPage, TargetProbePage } from "@/pages/attacker"
import { BugkuPage } from "@/pages/bugku"
import { ConnectionPage, MonitorPage } from "@/pages/connection"
import { BackupPage, WafPage } from "@/pages/operations"
import { PacketsPage } from "@/pages/packets"
import { Overview, type Page } from "@/pages/overview"
import { PwnPage } from "@/pages/pwn"
import { PwnForwardPage } from "@/pages/pwn-forward"
import { ScannerPage } from "@/pages/scanner"
import { TerminalPage } from "@/pages/terminal"
import { callDesktop, errorText, type WindowCommand } from "@/lib/desktop"
import "./styles.css"

const groups: { label: string; items: { page: Page; label: string; icon: LucideIcon }[] }[] = [
  {
    label: "工作台",
    items: [
      { page: "overview", label: "防御概览", icon: LayoutDashboard },
      { page: "ssh", label: "SSH 连接", icon: Server },
    ],
  },
  {
    label: "服务器管理",
    items: [
      { page: "terminal", label: "SSH 交互终端", icon: Terminal },
      { page: "monitor", label: "文件监控", icon: FolderClock },
      { page: "backup", label: "源码备份", icon: Archive },
    ],
  },
  {
    label: "站点防御",
    items: [
      { page: "scan", label: "WebShell 查杀", icon: FileSearch },
      { page: "waf", label: "WAF 管理", icon: Shield },
      { page: "pwn", label: "PWN 沙箱防护", icon: ShieldEllipsis },
      { page: "pwnForward", label: "PWN 流量转发", icon: Network },
      { page: "packets", label: "请求审查", icon: ScrollText },
      { page: "activity", label: "系统日志", icon: Activity },
    ],
  },
  {
    label: "站点攻击",
    items: [
      { page: "probe", label: "目标探活", icon: Search },
      { page: "attacker", label: "攻击辅助", icon: Crosshair },
    ],
  },
  {
    label: "平台工具",
    items: [
      { page: "bugku", label: "Bugku 批量提交", icon: Flag },
    ],
  },
]

function App() {
  return (
    <SidebarProvider className="h-svh min-h-0 overflow-hidden"
      style={{ "--sidebar-width": "14rem" } as CSSProperties}>
      <Workspace />
    </SidebarProvider>
  )
}

function Workspace() {
  const workspace = useWorkspace()
  const { setOpenMobile } = useSidebar()
  const { state, issue, offline, run, setIssue } = workspace
  const [page, setPage] = useState<Page>("overview")
  const [visited, setVisited] = useState<Page[]>(["overview"])
  const [dark, setDark] = useState(false)
  const [packetReview, setPacketReview] = useState<{ connection: string; id: number } | null>(null)
  const content = useRef<HTMLDivElement>(null)
  const connectionKey = JSON.stringify(state?.connection ?? null)
  const packetSync = state?.packetSync
  const caption = state?.window
  const maximizeLabel = caption?.maximized ? "还原窗口" : "最大化窗口"
  const sshLabel = state?.connection ? `SSH · ${state.connection.host}` : "SSH 未连接"
  const themeLabel = dark ? "切换到浅色主题" : "切换到深色主题"

  useEffect(() => { document.documentElement.classList.toggle("dark", dark) }, [dark])

  function go(next: Page) {
    setOpenMobile(false)
    if (page === next) return
    setVisited((old) => old.includes(next) ? old : [...old, next])
    setPage(next)
    setIssue("")
    content.current?.scrollTo({ top: 0 })
  }

  function acknowledgeHits(review: boolean) {
    if (!packetSync) return
    if (review) {
      setPacketReview((previous) => ({ connection: connectionKey, id: (previous?.id ?? 0) + 1 }))
      go("packets")
      content.current?.scrollTo({ top: 0 })
    }
    void run("ack-packet-hits", { through: packetSync.hitCursor })
  }

  async function controlWindow(command: WindowCommand) {
    try {
      await callDesktop("window_control", command)
    } catch (error) {
      setIssue(errorText(error))
    }
  }

  const pages = {
    overview: <Overview workspace={workspace} go={go} />,
    ssh: <ConnectionPage workspace={workspace} />,
    terminal: <TerminalPage key={connectionKey} workspace={workspace} active={page === "terminal"}
      openConnection={() => go("ssh")} />,
    monitor: <MonitorPage workspace={workspace} />,
    scan: <ScannerPage workspace={workspace} />,
    waf: <WafPage workspace={workspace} />,
    pwn: <PwnPage workspace={workspace} />,
    pwnForward: <PwnForwardPage workspace={workspace} />,
    packets: <PacketsPage workspace={workspace} openWaf={() => go("waf")}
      hitReview={packetReview?.connection === connectionKey ? packetReview.id : 0} />,
    backup: <BackupPage workspace={workspace} />,
    probe: <TargetProbePage workspace={workspace} />,
    attacker: <AttackerPage workspace={workspace} />,
    bugku: <BugkuPage workspace={workspace} active={page === "bugku"} />,
    activity: <>
      <PageHeading title="系统日志" description="查看本次会话的连接、查杀、WAF 与备份操作。" />
      <LogPanel events={state?.events ?? []} full />
    </>,
  }

  return (
    <>
      <Sidebar collapsible="icon">
        <SidebarHeader className="h-15 px-3 py-2 group-data-[collapsible=icon]:px-2">
          <SidebarMenu><SidebarMenuItem>
            <SidebarMenuButton size="lg" className="h-11 gap-2.5 group-data-[collapsible=icon]:p-0!"
              onClick={() => go("overview")} aria-label="MetaAWD 防御概览">
              <Badge className="size-8 shrink-0 rounded-md p-0 [&>svg]:size-4">
                <ShieldCheck aria-hidden />
              </Badge>
              <span className="text-base font-semibold tracking-tight text-foreground">MetaAWD</span>
            </SidebarMenuButton>
          </SidebarMenuItem></SidebarMenu>
        </SidebarHeader>
        <SidebarSeparator className="mx-0 data-[orientation=horizontal]:w-auto" />
        <SidebarContent role="navigation" aria-label="防御工作台导航" className="gap-1 pt-2">
          {groups.map((group) => <SidebarGroup key={group.label} className="px-3 group-data-[collapsible=icon]:px-2">
            <SidebarGroupLabel className="text-muted-foreground">{group.label}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map(({ page: key, label, icon: Icon }) => (
                  <SidebarMenuItem key={key}>
                    <SidebarMenuButton isActive={page === key} tooltip={label} aria-label={label} className="h-9 gap-2.5"
                      aria-current={page === key ? "page" : undefined} onClick={() => go(key)}>
                      <Icon aria-hidden /><span>{label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>)}
        </SidebarContent>
        <SidebarSeparator className="data-[orientation=horizontal]:w-auto" />
        <SidebarFooter className="px-3 group-data-[collapsible=icon]:px-2">
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton onClick={() => go("ssh")} tooltip={sshLabel} aria-label="查看 SSH 连接状态">
                {state?.connection ? <CircleCheck aria-hidden /> : <Unplug aria-hidden />}
                <span>{sshLabel}</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
            <SidebarMenuItem>
              <SidebarMenuButton onClick={() => setDark(!dark)} tooltip={themeLabel} aria-label={themeLabel}>
                {dark ? <Sun aria-hidden /> : <Moon aria-hidden />}
                <span>{dark ? "浅色主题" : "深色主题"}</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>
      <SidebarInset className="min-h-0 min-w-0 overflow-hidden bg-muted">
        <div className="flex h-10 shrink-0 items-center gap-2 px-3">
          <SidebarTrigger aria-label="折叠或展开侧栏" title="折叠或展开侧栏" />
          <div className={caption?.controls && !caption.maximized
            ? "pywebview-drag-region h-full flex-1 select-none" : "h-full flex-1"}
            onDoubleClick={caption?.controls ? () => void controlWindow("toggle-maximize") : undefined} />
          {caption?.controls && (
            <div className="flex items-center gap-1" role="group" aria-label="窗口操作">
              <Button variant="ghost" size="icon-sm" aria-label="最小化窗口" title="最小化窗口"
                onClick={() => void controlWindow("minimize")}><Minus aria-hidden /></Button>
              <Button variant="ghost" size="icon-sm" aria-label={maximizeLabel} title={maximizeLabel}
                onClick={() => void controlWindow("toggle-maximize")}>
                {caption.maximized ? <Copy aria-hidden /> : <Square aria-hidden />}
              </Button>
              <Button variant="ghost" size="icon-sm" aria-label="关闭窗口" title="关闭窗口"
                className="hover:text-destructive" onClick={() => void controlWindow("close")}><X aria-hidden /></Button>
            </div>
          )}
        </div>
        {packetSync && packetSync.unreadHits > 0 && (
          <div className="mx-auto w-full max-w-[1440px] shrink-0 px-4 pt-3 sm:px-6 lg:px-8">
            <Alert variant="destructive" className="items-center py-2 [&>svg]:translate-y-0" aria-label="新的 WAF 命中">
              <ShieldAlert aria-hidden />
              <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                <AlertTitle className="line-clamp-none">新同步 {packetSync.unreadHits} 条 WAF 命中</AlertTitle>
                <div className="flex items-center gap-1">
                  <Button size="sm" variant="outline" onClick={() => acknowledgeHits(true)}>查看命中</Button>
                  <Button size="icon-sm" variant="ghost" aria-label="关闭命中提示"
                    onClick={() => acknowledgeHits(false)}><X aria-hidden /></Button>
                </div>
              </div>
            </Alert>
          </div>
        )}
        <div ref={content} className="min-h-0 flex-1 overflow-auto">
          <div className="mx-auto grid max-w-[1440px] gap-3 px-4 py-5 sm:px-6 lg:px-8 lg:py-7">
            {offline && <Message>工作台运行服务尚未连接。请通过 MetaAWD 桌面窗口启动。</Message>}
            {issue && <Message>{issue}</Message>}
            {visited.map((key) => (
              <section className={page === key ? "grid gap-5" : "hidden"} key={key} hidden={page !== key}>{pages[key]}</section>
            ))}
          </div>
        </div>
      </SidebarInset>
    </>
  )
}

createRoot(document.getElementById("root")!).render(<App />)
