import * as path from "node:path";

import * as vscode from "vscode";

import type { VaultController, VaultSession } from "./controller.ts";
import type { TreeEntry } from "./sidecar.ts";

export interface InexTreeNode {
  readonly entry: TreeEntry;
  readonly session: VaultSession;
}

export class InexTreeProvider
  implements vscode.TreeDataProvider<InexTreeNode>, vscode.Disposable
{
  private readonly changeEmitter = new vscode.EventEmitter<InexTreeNode | undefined>();
  private readonly stateSubscription: vscode.Disposable;

  public readonly onDidChangeTreeData = this.changeEmitter.event;

  public constructor(private readonly controller: VaultController) {
    this.stateSubscription = controller.onDidChangeState(() => {
      this.refresh();
    });
  }

  public getTreeItem(element: InexTreeNode): vscode.TreeItem {
    const entry = element.entry;
    const item = new vscode.TreeItem(
      path.posix.basename(entry.logicalPath),
      entry.kind === "directory"
        ? vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None,
    );
    item.contextValue = `inex.${entry.kind}`;
    item.iconPath = new vscode.ThemeIcon(
      entry.kind === "directory"
        ? "folder"
        : entry.kind === "asset"
          ? "file-media"
          : "lock",
    );
    item.tooltip = entry.logicalPath;
    if (entry.kind === "file") {
      item.command = {
        command: "inex.internal.openTreeEntry",
        title: "Open Encrypted Markdown",
        arguments: [element],
      };
    }
    return item;
  }

  public async getChildren(element?: InexTreeNode): Promise<InexTreeNode[]> {
    if (!this.controller.isUnlocked) {
      return [];
    }
    const session = element?.session ?? this.controller.acquireSession();
    if (!this.controller.isSessionCurrent(session)) {
      return [];
    }
    const base = element?.entry.logicalPath;
    const entries = await this.controller.listTreeForSession(session, base);
    return entries.filter((entry) => {
      const relative =
        base === undefined
          ? entry.logicalPath
          : entry.logicalPath.startsWith(`${base}/`)
            ? entry.logicalPath.slice(base.length + 1)
            : "";
      return relative.length > 0 && !relative.includes("/");
    }).map((entry) => ({ entry, session }));
  }

  public async openNode(node: InexTreeNode): Promise<void> {
    if (
      node.entry.kind !== "file" ||
      !this.controller.isSessionCurrent(node.session)
    ) {
      throw new Error("Inex tree entry belongs to a locked or replaced vault session");
    }
    await vscode.commands.executeCommand(
      "vscode.openWith",
      this.controller.ciphertextUriForSession(node.entry.logicalPath, node.session),
      "inex.markdownEditor",
    );
    if (!this.controller.isSessionCurrent(node.session)) {
      throw new Error("Inex vault session changed while opening the tree entry");
    }
  }

  public refresh(): void {
    this.changeEmitter.fire(undefined);
  }

  public dispose(): void {
    this.stateSubscription.dispose();
    this.changeEmitter.dispose();
  }
}
