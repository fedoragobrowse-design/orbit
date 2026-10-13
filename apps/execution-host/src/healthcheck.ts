import { createConnection } from "node:net";

const SOCKET_PATH = process.env.EXEC_HOST_SOCKET ?? "/run/orbit-exec-host.sock";

// Compose health probe: connect to the private Unix socket, issue a ping
// frame, and require an ok response. Exits nonzero on any failure.
const socket = createConnection(SOCKET_PATH);
let buffer = "";
const timeout = setTimeout(() => {
  console.error("healthcheck timed out");
  process.exit(1);
}, 5000);
timeout.unref();

socket.setEncoding("utf8");
socket.on("connect", () => {
  socket.write(`${JSON.stringify({ id: "health", op: "ping" })}\n`);
});
socket.on("data", (chunk: string) => {
  buffer += chunk;
  const newline = buffer.indexOf("\n");
  if (newline < 0) return;
  try {
    const frame: unknown = JSON.parse(buffer.slice(0, newline));
    if (frame !== null && typeof frame === "object" && "ok" in frame && frame.ok === true) {
      clearTimeout(timeout);
      process.exit(0);
    }
  } catch {
    /* fall through to failure */
  }
  console.error("unhealthy response");
  process.exit(1);
});
socket.on("error", (cause: Error) => {
  console.error(`healthcheck failed: ${cause.message}`);
  process.exit(1);
});
