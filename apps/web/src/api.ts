import { QueryClient } from "@tanstack/react-query";
export type RecordData = { id: string; [key: string]: unknown };
export type Page<T = RecordData> = { items: T[]; next_cursor: string | null };
export type Session = {
  user: { id: string; email: string; display_name: string };
  csrf_token: string;
};
export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public requestId: string,
    public status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
let csrf = "";
export function setSession(session: Session | null) {
  csrf = session?.csrf_token ?? "";
}
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false, staleTime: 15_000, refetchOnWindowFocus: true },
  },
});
export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (
    options.body &&
    !(options.body instanceof FormData) &&
    !headers.has("Content-Type")
  )
    headers.set("Content-Type", "application/json");
  if (options.method && !["GET", "HEAD"].includes(options.method))
    headers.set("X-CSRF-Token", csrf);
  let response: Response;
  try {
    response = await fetch(
      path.startsWith("/api/") || path === "/ready" || path === "/health"
        ? path
        : `/api/v1${path}`,
      { ...options, headers, credentials: "same-origin" },
    );
  } catch {
    throw new ApiError(
      "CONNECTION_UNAVAILABLE",
      "Orbit could not be reached. Your draft is still here. Check the server and try again.",
      "",
      0,
    );
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new ApiError(
      body?.error?.code ?? "HTTP_ERROR",
      body?.error?.message ?? `Request failed (${response.status}).`,
      body?.error?.request_id ?? "",
      response.status,
    );
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}
export function post<T>(path: string, body: unknown = {}) {
  return api<T>(path, { method: "POST", body: JSON.stringify(body) });
}
export function put<T>(path: string, body: unknown) {
  return api<T>(path, { method: "PUT", body: JSON.stringify(body) });
}
export function remove(path: string) {
  return api<void>(path, { method: "DELETE" });
}
export function text(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  return JSON.stringify(value, null, 2);
}
export function title(row: RecordData) {
  return text(
    row.title ||
      row.name ||
      row.subject ||
      row.tool_name ||
      row.event_type ||
      row.action ||
      row.id,
  );
}
export function label(value: unknown) {
  return text(value)
    .toLowerCase()
    .replaceAll("_", " ")
    .replace(/^./, (s) => s.toUpperCase());
}
export function timestamp(value: unknown) {
  const date = new Date(text(value));
  return Number.isNaN(date.getTime())
    ? "Time unavailable"
    : date.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      });
}
