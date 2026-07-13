export const OPEN_NEW_VAULT_ACTION = "Open New Vault";

const IMPORT_COMPLETE_MESSAGE =
  "The Markdown repository was copied into a new encrypted Inex repository. Open the new vault as this workspace? VS Code will reload; then unlock it explicitly.";

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
