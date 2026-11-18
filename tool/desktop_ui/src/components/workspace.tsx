import { useEffect, useId, useRef, useState, type ChangeEvent, type ReactNode } from "react"
import { CircleAlert, FolderOpen, Terminal } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Empty as UiEmpty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Field as UiField, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from "@/components/ui/input-group"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Spinner } from "@/components/ui/spinner"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { cn } from "@/lib/utils"
import { areaLabels, callDesktop, errorText, timeOf, type Area, type EventEntry, type Snapshot } from "@/lib/desktop"

export function useWorkspace() {
  const [state, setState] = useState<Snapshot | null>(null)
  const [issue, setIssue] = useState("")
  const [offline, setOffline] = useState(false)
  const [pending, setPending] = useState(false)
  const requestNumber = useRef(0)

  async function refresh() {
    const id = ++requestNumber.current
    const data = await callDesktop("snapshot")
    if (id === requestNumber.current) {
      setState(data)
      setOffline(false)
    }
    return data
  }

  useEffect(() => {
    let disposed = false
    let timer: number
    const started = Date.now()

    async function poll() {
      let delay = 1000
      try {
        if (window.pywebview?.api?.invoke) {
          const data = await refresh()
          if (data.job || data.monitor.state !== "idle" || data.terminal.phase !== "idle" || data.bugku.running) {
            delay = 450
          }
        } else {
          if (Date.now() - started > 2500) setOffline(true)
          delay = 300
        }
      } catch {
        setOffline(true)
      }
      if (!disposed) timer = window.setTimeout(poll, delay)
    }
    void poll()
    return () => {
      disposed = true
      requestNumber.current += 1
      window.clearTimeout(timer)
    }
  }, [])

  async function run(name: string, data: Record<string, unknown> = {}) {
    setIssue("")
    setPending(true)
    try {
      const result = await callDesktop("action", name, data)
      if (!result.ok) {
        setIssue(result.message ?? "操作未开始。")
        return false
      }
      await refresh()
      return true
    } catch (error) {
      setIssue(errorText(error))
      return false
    } finally {
      setPending(false)
    }
  }

  async function pick(kind: "directory" | "archive" | "file") {
    try {
      return await callDesktop("pick_path", kind)
    } catch (error) {
      setIssue(errorText(error))
      return null
    }
  }

  return { state, issue, setIssue, offline, pending, run, pick, busy: pending || !!state?.job }
}

export type Workspace = ReturnType<typeof useWorkspace>

export function PageHeading({ title, description, actions }: { title: string; description: string; actions?: ReactNode }) {
  return (
    <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h1 className="text-2xl leading-tight font-semibold tracking-tight lg:text-3xl">{title}</h1>
        <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{description}</p>
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}

export function Panel({ title, description, actions, className, children }: {
  title: string; description?: string; actions?: ReactNode; className?: string; children: ReactNode
}) {
  return (
    <Card className={cn("min-w-0 gap-4 py-5", className)}>
      <CardHeader className="gap-1.5 px-4 sm:px-5">
        <CardTitle className="text-base leading-snug" role="heading" aria-level={2}>{title}</CardTitle>
        {description && <CardDescription className="wrap-anywhere">{description}</CardDescription>}
        {actions && <CardAction className="flex flex-wrap items-center gap-2">{actions}</CardAction>}
      </CardHeader>
      <CardContent className="min-w-0 px-4 sm:px-5">{children}</CardContent>
    </Card>
  )
}

export function Field({ label, hint, children }: {
  label: string; hint?: string; children: (id: string) => ReactNode
}) {
  const id = useId()
  return (
    <UiField>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      {children(id)}
      {hint && <FieldDescription>{hint}</FieldDescription>}
    </UiField>
  )
}

export function PathInput({ id, value, onChange, pick, placeholder, disabled }: {
  id: string; value: string; onChange: (value: string) => void; pick?: () => void
  placeholder?: string; disabled?: boolean
}) {
  const props = {
    id, value, placeholder, disabled, spellCheck: false, autoComplete: "off",
    onChange: (event: ChangeEvent<HTMLInputElement>) => onChange(event.target.value),
  }
  if (!pick) return <Input {...props} />
  return (
    <InputGroup>
      <InputGroupInput {...props} />
      <InputGroupAddon align="inline-end">
        <InputGroupButton onClick={pick} disabled={disabled}><FolderOpen />浏览</InputGroupButton>
      </InputGroupAddon>
    </InputGroup>
  )
}

export function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <UiEmpty className="border-0 bg-muted px-4 py-5 md:p-6">
      <EmptyHeader>
        <EmptyMedia variant="icon" className="bg-card text-primary">{icon}</EmptyMedia>
        <EmptyTitle className="text-base font-semibold">{title}</EmptyTitle>
        {children && <EmptyDescription>{children}</EmptyDescription>}
      </EmptyHeader>
    </UiEmpty>
  )
}

export function Status({ children, tone = "neutral" }: {
  children: ReactNode; tone?: "neutral" | "good" | "warn" | "error"
}) {
  const variants = { neutral: "secondary", good: "default", warn: "outline", error: "destructive" } as const
  return <Badge variant={variants[tone]}>{children}</Badge>
}

export function Message({ children }: { children: ReactNode }) {
  return <Alert variant="destructive"><CircleAlert /><AlertDescription>{children}</AlertDescription></Alert>
}

export function Busy({ label }: { label: string }) {
  return <><Spinner />{label}</>
}

export function LogPanel({ events, area, title = "操作日志", full = false }: {
  events: EventEntry[]; area?: Area; title?: string; full?: boolean
}) {
  const matching = area ? events.filter((entry) => entry.area === area) : events
  const shown = matching.slice(full ? -160 : -40).reverse()
  return (
    <Panel title={title} className="min-w-0">
      {shown.length ? (
        <ScrollArea className={full ? undefined : "[&_[data-slot=scroll-area-viewport]]:max-h-72"}>
          <Table aria-label={title}>
            <TableBody>{shown.map((entry) => (
              <TableRow key={entry.id}>
                <TableCell className="w-20 align-top font-mono text-xs text-muted-foreground">
                  <time>{timeOf(entry.time)}</time>
                </TableCell>
                <TableCell className="min-w-0 whitespace-normal wrap-anywhere">
                  {!area && <Badge variant="outline" className="mr-2">{areaLabels[entry.area]}</Badge>}
                  {entry.level === "error" && <Badge variant="destructive" className="mr-2">失败</Badge>}
                  {entry.message}
                </TableCell>
              </TableRow>
            ))}</TableBody>
          </Table>
        </ScrollArea>
      ) : <Empty title="暂无操作日志" icon={<Terminal />} />}
    </Panel>
  )
}

export function Confirm({ title, description, label, onConfirm, disabled, children }: {
  title: string; description: string; label: string; onConfirm: () => void
  disabled?: boolean; children: ReactNode
}) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild><Button variant="outline" disabled={disabled}>{children}</Button></AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>取消</AlertDialogCancel>
          <AlertDialogAction variant="destructive" onClick={onConfirm}>{label}</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
