import type { UmbraStatus } from "./sidecar.ts";

export function formatSecurityStatus(
  outerUnlocked: boolean,
  umbra: UmbraStatus | undefined,
): string {
  if (!outerUnlocked) {
    return "Inex Outer vault is locked. Umbra private data is unavailable.";
  }
  if (umbra === undefined) {
    return "Inex Outer vault is unlocked in memory. Umbra status could not be verified; private data remains unavailable until it is explicitly unlocked.";
  }
  if (!umbra.initialized) {
    return "Inex Outer vault is unlocked in memory. Umbra has not been initialized; no Umbra private session is active.";
  }
  if (!umbra.unlocked) {
    return "Inex Outer vault is unlocked in memory. Umbra is initialized but locked; private data is unavailable.";
  }
  return "Inex Outer vault and Umbra are unlocked in memory. Lock Umbra when private editing is finished.";
}
