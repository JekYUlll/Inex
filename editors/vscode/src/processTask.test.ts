import assert from "node:assert/strict";
import test from "node:test";

import {
  type ProcessTaskDisposable,
  type ProcessTaskLifecycle,
  runProcessTask,
} from "./processTask.ts";

interface Execution {
  readonly id: number;
}

class Lifecycle implements ProcessTaskLifecycle<Execution> {
  public readonly execution = { id: 1 };
  public disposed = 0;
  public startAction: () => PromiseLike<Execution> = () =>
    Promise.resolve(this.execution);
  private processStartListener: ((execution: Execution) => void) | undefined;
  private processEndListener:
    | ((execution: Execution, exitCode: number | undefined) => void)
    | undefined;
  private taskEndListener: ((execution: Execution) => void) | undefined;

  public start(): PromiseLike<Execution> {
    return this.startAction();
  }

  public onProcessStart(listener: (execution: Execution) => void): ProcessTaskDisposable {
    this.processStartListener = listener;
    return this.disposable();
  }

  public onProcessEnd(
    listener: (execution: Execution, exitCode: number | undefined) => void,
  ): ProcessTaskDisposable {
    this.processEndListener = listener;
    return this.disposable();
  }

  public onTaskEnd(listener: (execution: Execution) => void): ProcessTaskDisposable {
    this.taskEndListener = listener;
    return this.disposable();
  }

  public processStart(execution: Execution = this.execution): void {
    this.processStartListener?.(execution);
  }

  public processEnd(exitCode: number | undefined, execution: Execution = this.execution): void {
    this.processEndListener?.(execution, exitCode);
  }

  public taskEnd(execution: Execution = this.execution): void {
    this.taskEndListener?.(execution);
  }

  private disposable(): ProcessTaskDisposable {
    let disposed = false;
    return {
      dispose: () => {
        if (!disposed) {
          disposed = true;
          this.disposed += 1;
        }
      },
    };
  }
}

test("process task captures a process exit that races ahead of start resolution", async () => {
  const lifecycle = new Lifecycle();
  lifecycle.startAction = () => {
    lifecycle.processStart();
    lifecycle.processEnd(0);
    lifecycle.taskEnd();
    return Promise.resolve(lifecycle.execution);
  };

  assert.equal(await runProcessTask(lifecycle), 0);
  assert.equal(lifecycle.disposed, 3);
});

test("process task waits for process status when the task-end event arrives first", async () => {
  const lifecycle = new Lifecycle();
  const result = runProcessTask(lifecycle);
  await Promise.resolve();
  lifecycle.processStart();
  lifecycle.taskEnd();
  lifecycle.processEnd(17);

  assert.equal(await result, 17);
  assert.equal(lifecycle.disposed, 3);
});

test("process task reports a task that ended without starting a process", async () => {
  const lifecycle = new Lifecycle();
  const result = runProcessTask(lifecycle);
  await Promise.resolve();
  lifecycle.taskEnd();

  assert.equal(await result, undefined);
  assert.equal(lifecycle.disposed, 3);
});

test("process task disposes all listeners when start throws synchronously", async () => {
  const lifecycle = new Lifecycle();
  lifecycle.startAction = () => {
    throw new Error("start rejected");
  };

  await assert.rejects(runProcessTask(lifecycle), /start rejected/u);
  assert.equal(lifecycle.disposed, 3);
});
