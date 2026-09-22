import { isMeshNetworkFailure, MeshTerminalError } from "@meta-uber/mesh-transport"

export type WorkspaceJoinResponse = { kind: "accepted"; payload: Uint8Array } | { kind: "rejected"; error: string }
export type WorkspaceJoinAck = { kind: "accepted"; payload: Uint8Array } | { kind: "rejected"; error: string }

export type WorkspaceJoinMachine = {
  sendRequest(payload: Uint8Array): Uint8Array
  receiveRequest(frame: Uint8Array): Uint8Array
  respond(payload: Uint8Array): Uint8Array
  reject(message: string): Uint8Array
  receiveResponse(frame: Uint8Array): WorkspaceJoinResponse
  acknowledgeRejection(): Uint8Array
  acknowledgeSuccess(payload: Uint8Array): Uint8Array
  rejectAcceptedResponse(message: string): Uint8Array
  receiveAck(frame: Uint8Array): WorkspaceJoinAck
}

export type WorkspaceJoinStream = {
  send(bytes: Uint8Array): Promise<void>
  read(): Promise<Uint8Array>
  closeSend(): Promise<void>
}

export type WorkspaceJoinConnection = {
  openStream(): Promise<WorkspaceJoinStream>
  acceptStream(): Promise<WorkspaceJoinStream>
}

export type WorkspaceJoinHandoffMachine = {
  guestRequest(): Uint8Array
  hostReceiveRequest(frame: Uint8Array): Uint8Array
  guestReceiveReady(frame: Uint8Array): void
  guestTransportFailed(retryable: boolean): string
  guestResumeSucceeded(): void
  guestResumeFailed(retryable: boolean): string
  guestBeginConfirmation(): Uint8Array
  guestConfirmationSent(): string
  guestConfirmationFailed(): string
  hostReceiveConfirmation(frame: Uint8Array): void
}

export type WorkspaceJoinHandoffOutcome =
  | { kind: "retry" }
  | { kind: "adopted"; confirmationSent: boolean; error?: unknown }

/** Browser stream effects around Rust-owned authenticated handoff transitions. */
export class BrowserWorkspaceJoinHandoffGuest {
  constructor(private readonly machine: WorkspaceJoinHandoffMachine) {}

  async run(connection: WorkspaceJoinConnection, resumeMesh: () => Promise<void>, rollbackResume: () => Promise<void>): Promise<WorkspaceJoinHandoffOutcome> {
    let request: WorkspaceJoinStream
    try {
      const requestFrame = this.machine.guestRequest()
      request = await connection.openStream()
      await request.send(requestFrame)
      await request.closeSend()
      this.machine.guestReceiveReady(await request.read())
    } catch (error) {
      const outcome = this.machine.guestTransportFailed(isMeshNetworkFailure(error))
      if (outcome === "retry") return { kind: "retry" }
      throw error
    }

    try {
      await resumeMesh()
      this.machine.guestResumeSucceeded()
    } catch (error) {
      const outcome = this.machine.guestResumeFailed(isMeshNetworkFailure(error))
      try { await rollbackResume() }
      catch (rollbackError) {
        throw new WorkspaceJoinHandoffRollbackError(error, rollbackError)
      }
      if (outcome === "retry") return { kind: "retry" }
      throw error
    }

    const confirmationFrame = this.machine.guestBeginConfirmation()
    try {
      const confirmation = await connection.openStream()
      await confirmation.send(confirmationFrame)
      await confirmation.closeSend()
      const outcome = this.machine.guestConfirmationSent()
      if (outcome !== "complete") throw new Error("Workspace handoff completion invalid")
      return { kind: "adopted", confirmationSent: true }
    } catch (error) {
      const outcome = this.machine.guestConfirmationFailed()
      if (outcome === "adopted") return { kind: "adopted", confirmationSent: false, error }
      throw error
    }
  }
}

export class BrowserWorkspaceJoinHandoffHost {
  constructor(private readonly machine: WorkspaceJoinHandoffMachine) {}

  async run(stream: WorkspaceJoinStream, requestFrame: Uint8Array, connection: WorkspaceJoinConnection) {
    const ready = this.machine.hostReceiveRequest(requestFrame)
    await stream.send(ready)
    await stream.closeSend()
    const confirmation = await connection.acceptStream()
    try { this.machine.hostReceiveConfirmation(await confirmation.read()) }
    finally { await confirmation.closeSend() }
  }
}

export class WorkspaceJoinHandoffRollbackError extends MeshTerminalError {
  constructor(cause: unknown, rollbackCause: unknown) {
    super(`Workspace mesh rollback failed: ${errorText(rollbackCause)}`)
    this.name = "WorkspaceJoinHandoffRollbackError"
    Object.defineProperty(this, "cause", { value: cause, configurable: true })
  }
}

function errorText(error: unknown) { return error instanceof Error ? error.message : String(error) }

export type WorkspaceJoinApproval<T> = { ok: true; value: T } | { ok: false; error: string }
export type WorkspaceJoinHostCallbacks<Request, Approval> = {
  request(payload: Uint8Array): Request
  approve(request: Request): Promise<WorkspaceJoinApproval<Approval>>
  prepare(approval: Approval): Promise<Uint8Array>
  acknowledged?(payload: Uint8Array): Promise<void>
}

/** A peer's authenticated application rejection. Always terminal, even when its text mentions network failures. */
export class WorkspaceJoinRejectedError extends MeshTerminalError {
  constructor(message: string, cause?: unknown) {
    super(message)
    this.name = "WorkspaceJoinRejectedError"
    if (cause !== undefined) Object.defineProperty(this, "cause", { value: cause, configurable: true })
  }
}

/** Browser stream effects for transitions owned by the Rust join machine. */
export class BrowserWorkspaceJoinHost {
  constructor(private readonly machine: WorkspaceJoinMachine) {}

  async handle<Request, Approval>(requestFrame: Uint8Array, stream: WorkspaceJoinStream, connection: WorkspaceJoinConnection,
    callbacks: WorkspaceJoinHostCallbacks<Request, Approval>) {
    const request = this.machine.receiveRequest(requestFrame)
    let appRequest: Request
    try { appRequest = callbacks.request(request) }
    catch (error) { return this.rejectFailure(stream, connection, error) }

    let decision: WorkspaceJoinApproval<Approval>
    try { decision = await callbacks.approve(appRequest) }
    catch (error) { return this.rejectFailure(stream, connection, error) }
    if (!decision.ok) {
      try { await this.sendRejection(stream, connection, decision.error) } catch { /* Declined request remains terminal for the guest if delivery succeeded. */ }
      return { kind: "declined" as const }
    }

    let payload: Uint8Array
    try { payload = await callbacks.prepare(decision.value) }
    catch (error) { return this.rejectFailure(stream, connection, error) }

    const acknowledgement = await this.exchange(stream, connection, this.machine.respond(payload))
    await callbacks.acknowledged?.(acknowledgement.payload)
    return { kind: "accepted" as const, value: decision.value }
  }

  private async rejectFailure(stream: WorkspaceJoinStream, connection: WorkspaceJoinConnection, error: unknown): Promise<never> {
    const message = error instanceof Error ? error.message : String(error)
    try { await this.sendRejection(stream, connection, message) } catch { /* Keep the preparation cause visible on the host. */ }
    throw new WorkspaceJoinRejectedError(message, error)
  }

  private async sendRejection(stream: WorkspaceJoinStream, connection: WorkspaceJoinConnection, message: string) {
    await this.exchange(stream, connection, this.machine.reject(message))
  }

  private async exchange(stream: WorkspaceJoinStream, connection: WorkspaceJoinConnection, response: Uint8Array) {
    await stream.send(response)
    await stream.closeSend()
    return this.receiveAck(connection)
  }

  private async receiveAck(connection: WorkspaceJoinConnection) {
    const result = await withTimeout(async () => {
      const acknowledgement = await connection.acceptStream()
      try { return this.machine.receiveAck(await acknowledgement.read()) }
      finally { await acknowledgement.closeSend() }
    }, 20_000)
    if (result.kind === "rejected") throw new WorkspaceJoinRejectedError(result.error)
    return result
  }
}

/** Guest adapter preserves Rust's terminal rejection result instead of classifying message text. */
export class BrowserWorkspaceJoinGuest {
  constructor(private readonly machine: WorkspaceJoinMachine) {}

  async handle<RequestResult>(stream: WorkspaceJoinStream, connection: WorkspaceJoinConnection, request: Uint8Array,
    install: (payload: Uint8Array) => Promise<{ value: RequestResult; acknowledgement: Uint8Array }>): Promise<RequestResult> {
    await stream.send(this.machine.sendRequest(request))
    await stream.closeSend()
    const response = this.machine.receiveResponse(await stream.read())
    if (response.kind === "rejected") {
      let acknowledgementError: unknown
      try { await this.acknowledgeRejection(connection) } catch (error) { acknowledgementError = error }
      throw new WorkspaceJoinRejectedError(response.error, acknowledgementError)
    }
    let installed: { value: RequestResult; acknowledgement: Uint8Array }
    try { installed = await install(response.payload) }
    catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      try { await this.rejectAcceptedResponse(connection, message) } catch (ackError) {
        throw new WorkspaceJoinRejectedError(message, ackError)
      }
      throw new WorkspaceJoinRejectedError(message, error)
    }
    await this.acknowledgeSuccess(connection, installed.acknowledgement)
    return installed.value
  }

  async acknowledgeRejection(connection: WorkspaceJoinConnection) {
    const acknowledgement = await connection.openStream()
    await acknowledgement.send(this.machine.acknowledgeRejection())
    await acknowledgement.closeSend()
  }

  async acknowledgeSuccess(connection: WorkspaceJoinConnection, payload: Uint8Array) {
    const acknowledgement = await connection.openStream()
    await acknowledgement.send(this.machine.acknowledgeSuccess(payload))
    await acknowledgement.closeSend()
  }

  async rejectAcceptedResponse(connection: WorkspaceJoinConnection, message: string) {
    try {
      const acknowledgement = await connection.openStream()
      await acknowledgement.send(this.machine.rejectAcceptedResponse(message))
      await acknowledgement.closeSend()
    } catch (error) {
      throw new WorkspaceJoinRejectedError(message, error)
    }
  }

}

async function withTimeout<T>(operation: () => Promise<T>, milliseconds: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      operation(),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("Workspace join acknowledgement timed out.")), milliseconds) }),
    ])
  } finally { if (timer) clearTimeout(timer) }
}
