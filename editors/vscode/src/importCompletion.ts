export const OPEN_NEW_VAULT_ACTION = "Open New Vault";

const IMPORT_COMPLETE_MESSAGE =
  "Inex reported an initialized or reconciled, fully audited encrypted repository at the selected target. Fresh initialization leaves the source unchanged and does not copy its plaintext Git history. Open the encrypted repository as this workspace? VS Code will reload; then unlock it explicitly.";

export interface ImportedVaultTransition<T> {
  readonly prompt: (message: string, action: string) => Promise<string | undefined>;
  readonly openFolder: (target: T) => Promise<void>;
}

export async function offerToOpenImportedVault<T>(
  target: T,
  transition: ImportedVaultTransition<T>,
): Promise<boolean> {
  const choice = await transition.prompt(
    IMPORT_COMPLETE_MESSAGE,
    OPEN_NEW_VAULT_ACTION,
  );
  if (choice !== OPEN_NEW_VAULT_ACTION) {
    return false;
  }
  await transition.openFolder(target);
  return true;
}
