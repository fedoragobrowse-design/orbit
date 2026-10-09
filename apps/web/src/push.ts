import { post } from "./api";
function urlBase64ToUint8Array(base64: string): Uint8Array<ArrayBuffer> {
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const raw = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
type VapidKey = { public_key: string };
type PushSub = { endpoint: string; p256dh: string; auth: string };
function toPushSub(sub: PushSubscription): PushSub | null {
  const json = sub.toJSON() as { endpoint?: string; keys?: { p256dh?: string; auth?: string } };
  if (!json.endpoint || !json.keys?.p256dh || !json.keys?.auth) return null;
  return { endpoint: json.endpoint, p256dh: json.keys.p256dh, auth: json.keys.auth };
}
export async function syncPushSubscription(reg: ServiceWorkerRegistration): Promise<void> {
  try {
    if (!("pushManager" in reg) || !("Notification" in window)) return;
    if (Notification.permission === "denied") return;
    const existing = await reg.pushManager.getSubscription();
    const current = existing ? toPushSub(existing) : null;
    if (current) {
      try { await post("/push/subscribe", current); return; } catch { /* fall through and resubscribe */ }
    }
    if (Notification.permission === "default") return;
    let key: VapidKey;
    try { key = await post<VapidKey>("/push/vapid-key"); } catch { return; }
    if (!key.public_key) return;
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(key.public_key).buffer as ArrayBuffer });
    const payload = toPushSub(sub);
    if (!payload) return;
    await post("/push/subscribe", payload);
  } catch { /* push is best-effort; the in-app approvals list stays authoritative */ }
}
export async function enablePush(reg: ServiceWorkerRegistration): Promise<boolean> {
  try {
    if (!("pushManager" in reg) || !("Notification" in window)) return false;
    const permission = await Notification.requestPermission();
    if (permission !== "granted") return false;
    const key = await post<VapidKey>("/push/vapid-key");
    if (!key.public_key) return false;
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(key.public_key).buffer as ArrayBuffer });
    const payload = toPushSub(sub);
    if (!payload) return false;
    await post("/push/subscribe", payload);
    return true;
  } catch { return false; }
}
