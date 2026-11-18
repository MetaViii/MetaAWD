import { useEffect, useRef, useState } from "react"
import { Cable, CircleStop, Send, Terminal } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Busy, Field, Message, PageHeading, Panel, Status, type Workspace } from "@/components/workspace"
import { callDesktop, errorText, type TerminalState } from "@/lib/desktop"

const phases: Record<TerminalState["phase"], string> = {
  idle: "未打开", connecting: "正在连接", open: "会话已打开", closing: "正在断开",
}

export function TerminalPage({ workspace: { state, run, pending }, active, openConnection }: {
  workspace: Workspace
  active: boolean
  openConnection: () => void
}) {
  const terminal = state?.terminal
  const connection = state?.connection
  const phase = terminal?.phase ?? "idle"
  const opened = phase === "open"
  const [line, setLine] = useState("")
  const [output, setOutput] = useState("")
  const [readIssue, setReadIssue] = useState("")
  const viewport = useRef<HTMLTextAreaElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const follow = useRef(true)
  const revision = terminal?.revision

  useEffect(() => {
    if (!active || revision === undefined) return
    let ignore = false
    callDesktop("terminal_output").then((text) => {
      if (!ignore) {
        setOutput(text)
        setReadIssue("")
      }
    }).catch((error) => {
      if (!ignore) setReadIssue(errorText(error))
    })
    return () => { ignore = true }
  }, [active, revision])

  useEffect(() => {
    if (active && follow.current && viewport.current) {
      viewport.current.scrollTop = viewport.current.scrollHeight
    }
  }, [active, output])

  useEffect(() => {
    if (active && opened) input.current?.focus()
  }, [active, opened])

  return (
    <>
      <PageHeading title="SSH 交互终端" description="在已验证的服务器上打开持久会话，按行输入并查看实时输出。"
        actions={<Status tone={opened ? "good" : phase === "idle" ? "neutral" : "warn"}>{phases[phase]}</Status>} />
      <Panel title="终端"
        description={connection ? `${connection.user}@${connection.host}:${connection.port}` : "请先验证要管理的服务器。"}
        actions={!connection ? <Button size="sm" variant="outline" onClick={openConnection}><Cable />配置 SSH</Button>
          : phase === "idle" ? <Button size="sm" disabled={pending || state?.job === "connect"}
            onClick={() => { follow.current = true; void run("terminal-open") }}><Terminal />打开终端</Button>
            : <Button size="sm" variant="outline" disabled={pending || phase === "closing"}
              onClick={() => void run("terminal-close")}>
              {phase === "closing" ? <Busy label="断开中" /> : <><CircleStop />断开会话</>}
            </Button>}>
        <div className="grid min-w-0 gap-4">
          {terminal?.error && <Message>{terminal.error}</Message>}
          {readIssue && <Message>{readIssue}</Message>}
          <Textarea ref={viewport} readOnly value={output} wrap="off" spellCheck={false}
            aria-label="SSH 终端输出" placeholder={phase === "connecting" ? "正在打开 SSH 会话…" : "终端输出会显示在这里。"}
            className="h-[clamp(16rem,48vh,32rem)] resize-y overflow-auto bg-muted font-mono text-xs leading-relaxed"
            onScroll={({ currentTarget }) => {
              follow.current = currentTarget.scrollHeight - currentTarget.clientHeight - currentTarget.scrollTop < 24
            }} />
          <form className="grid items-end gap-3 sm:grid-cols-[minmax(0,1fr)_auto]"
            onSubmit={async (event) => {
              event.preventDefault()
              if (opened && !pending && await run("terminal-send", { line })) setLine("")
            }}>
            <Field label="终端输入">{(id) => <Input ref={input} id={id} value={line} maxLength={4096}
              onChange={(event) => setLine(event.target.value)} disabled={!opened} readOnly={pending}
              spellCheck={false} autoComplete="off" placeholder="输入一行并按 Enter" className="font-mono"
              onKeyDown={(event) => {
                const selected = event.currentTarget.selectionStart !== event.currentTarget.selectionEnd
                if (opened && !pending && !selected && event.ctrlKey && event.key.toLowerCase() === "c") {
                  event.preventDefault()
                  void run("terminal-interrupt")
                }
              }} />}</Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={!opened || pending}><Send />发送</Button>
              <Button type="button" variant="outline" disabled={!opened || pending}
                onClick={() => void run("terminal-interrupt")}>Ctrl+C 中断</Button>
            </div>
          </form>
        </div>
      </Panel>
    </>
  )
}
