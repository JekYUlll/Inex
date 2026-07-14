export interface ProcessTaskDisposable {
  dispose(): void;
}

export interface ProcessTaskLifecycle<Execution extends object> {
  readonly start: () => PromiseLike<Execution>;
  readonly onProcessStart: (
    listener: (execution: Execution) => void,
  ) => ProcessTaskDisposable;
  readonly onProcessEnd: (
    listener: (execution: Execution, exitCode: number | undefined) => void,
  ) => ProcessTaskDisposable;
  readonly onTaskEnd: (
    listener: (execution: Execution) => void,
  ) => ProcessTaskDisposable;
}

export function runProcessTask<Execution extends object>(
  lifecycle: ProcessTaskLifecycle<Execution>,
): Promise<number | undefined> {
  return new Promise((resolve, reject) => {
    let execution: Execution | undefined;
    let processStarted = false;
    const earlyProcessStarts: Execution[] = [];
    const earlyProcessEnds: Array<{
      readonly execution: Execution;
      readonly exitCode: number | undefined;
    }> = [];
    const earlyTaskEnds: Execution[] = [];
    let settled = false;
    let processStartSubscription: ProcessTaskDisposable | undefined;
    let processEndSubscription: ProcessTaskDisposable | undefined;
    let taskEndSubscription: ProcessTaskDisposable | undefined;

    const dispose = () => {
      processStartSubscription?.dispose();
      processEndSubscription?.dispose();
      taskEndSubscription?.dispose();
    };
    const finish = (exitCode: number | undefined) => {
      if (settled) {
        return;
      }
      settled = true;
      dispose();
      resolve(exitCode);
    };
    const fail = (error: unknown) => {
      if (settled) {
        return;
      }
      settled = true;
      dispose();
      reject(error);
    };

    try {
      processStartSubscription = lifecycle.onProcessStart((started) => {
        if (execution === undefined) {
          earlyProcessStarts.push(started);
        } else if (started === execution) {
          processStarted = true;
        }
      });
      processEndSubscription = lifecycle.onProcessEnd((ended, exitCode) => {
        if (execution === undefined) {
          earlyProcessEnds.push({ execution: ended, exitCode });
        } else if (ended === execution) {
          finish(exitCode);
        }
      });
      taskEndSubscription = lifecycle.onTaskEnd((ended) => {
        if (execution === undefined) {
          earlyTaskEnds.push(ended);
        } else if (ended === execution && !processStarted) {
          finish(undefined);
        }
      });
    } catch (error: unknown) {
      fail(error);
      return;
    }

    let started: PromiseLike<Execution>;
    try {
      started = lifecycle.start();
    } catch (error: unknown) {
      fail(error);
      return;
    }
    void Promise.resolve(started).then((running) => {
      execution = running;
      processStarted = earlyProcessStarts.includes(running);
      const processEnd = earlyProcessEnds.find((event) => event.execution === running);
      if (processEnd !== undefined) {
        finish(processEnd.exitCode);
        return;
      }
      if (earlyTaskEnds.includes(running) && !processStarted) {
        finish(undefined);
      }
    }, fail);
  });
}
