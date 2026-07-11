const MAX_LOGICAL_PATH_BYTES = 1024;
const MAX_COMPONENT_BYTES = 255;
const MAX_FILE_COMPONENT_BYTES = 251;

export class LogicalPathError extends Error {
  public override readonly name = "LogicalPathError";
}

export function logicalFileComponents(value: string): readonly string[] {
  const components = logicalComponents(value, false);
  const fileName = components.at(-1);
  if (fileName === undefined || !fileName.endsWith(".md")) {
    throw new LogicalPathError("Logical document path must end in lowercase .md");
  }
  if (Buffer.byteLength(fileName, "utf8") > MAX_FILE_COMPONENT_BYTES) {
    throw new LogicalPathError("Logical document filename exceeds the portable byte limit");
  }
  return components;
}

export function logicalDirectoryComponents(value: string): readonly string[] {
  return logicalComponents(value, true);
}

/** Build one file child without allowing an input value to smuggle separators. */
export function logicalFileChild(parent: string, name: string): string {
  const parentComponents = logicalDirectoryComponents(parent);
  validateChildName(name);
  const logicalPath = [...parentComponents, name].join("/");
  logicalFileComponents(logicalPath);
  return logicalPath;
}

/** Build one directory child without allowing an input value to smuggle separators. */
export function logicalDirectoryChild(parent: string, name: string): string {
  const parentComponents = logicalDirectoryComponents(parent);
  validateChildName(name);
  const logicalPath = [...parentComponents, name].join("/");
  if (logicalDirectoryComponents(logicalPath).length === 0) {
    throw new LogicalPathError("The vault root already exists");
  }
  return logicalPath;
}

function logicalComponents(value: string, allowRoot: boolean): readonly string[] {
  if (allowRoot && value.length === 0) {
    return [];
  }
  if (value.length === 0 || value.startsWith("/")) {
    throw new LogicalPathError("Logical path must be a non-empty relative path");
  }
  if (value.normalize("NFC") !== value) {
    throw new LogicalPathError("Logical path must use canonical Unicode NFC");
  }
  if (value.includes("\\")) {
    throw new LogicalPathError("Logical paths use / separators");
  }
  if (Buffer.byteLength(value, "utf8") > MAX_LOGICAL_PATH_BYTES) {
    throw new LogicalPathError("Logical path exceeds the portable byte limit");
  }

  const components = value.split("/");
  for (const [index, component] of components.entries()) {
    validateComponent(component);
    if (index === 0 && component.toLowerCase() === "vault.json") {
      throw new LogicalPathError("Logical path collides with vault metadata");
    }
  }
  return components;
}

function validateComponent(component: string): void {
  if (component.length === 0 || component === "." || component === "..") {
    throw new LogicalPathError("Logical path contains an invalid component");
  }
  if (Buffer.byteLength(component, "utf8") > MAX_COMPONENT_BYTES) {
    throw new LogicalPathError("Logical path component exceeds the portable byte limit");
  }
  if (component.startsWith(" ") || component.endsWith(" ") || component.endsWith(".")) {
    throw new LogicalPathError("Logical path component has unsafe edge characters");
  }
  if (/\p{Cc}/u.test(component) || /[<>:"|?*]/u.test(component)) {
    throw new LogicalPathError("Logical path component contains a forbidden character");
  }

  const lower = component.toLowerCase();
  if (lower === ".git" || lower === ".vault-local") {
    throw new LogicalPathError("Logical path enters reserved storage");
  }
  const basename = (component.split(".", 1)[0] ?? component).replace(/ +$/u, "");
  if (isWindowsDeviceBasename(basename) || /~[0-9]$/u.test(basename)) {
    throw new LogicalPathError("Logical path component is not portable to Windows/Git");
  }
}

function validateChildName(name: string): void {
  if (name.includes("/")) {
    throw new LogicalPathError("Enter one child name without / separators");
  }
  validateComponent(name);
}

function isWindowsDeviceBasename(value: string): boolean {
  const upper = value.toUpperCase();
  if (
    upper === "CON" ||
    upper === "PRN" ||
    upper === "AUX" ||
    upper === "NUL" ||
    upper === "CONIN$" ||
    upper === "CONOUT$"
  ) {
    return true;
  }
  return /^(?:COM|LPT)(?:[1-9]|[¹²³])$/u.test(upper);
}
