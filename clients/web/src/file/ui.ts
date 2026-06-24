// Minimal file-transfer UI: drag-and-drop send + receive-progress display (P7-2 — ADR-0024).
//
// This component is deliberately small but real: it wires the strict-typed `FileTransferSender` /
// `FileTransferReceiver` into a DOM affordance. It shows the file name, % progress, and an
// integrity-OK / failed indicator.
//
// The wire bytes are produced/parsed entirely by the Rust/wasm codec (via `framing.ts`); this file
// is presentation + driving glue only.
//
// NOTE (R-BROWSER-FILE, deferred): the live browser↔native file transfer over a real DataChannel
// is explicitly out of P7-2 scope, so there is no live transport here. The drop handler drives the
// in-process sender → receiver loop (the same validated state machines a transport would feed),
// which exercises the full offer → chunk → integrity-verify path end to end in the browser.

import { loadBridge } from "../bridge/index.js";
import type { ShBridge } from "../bridge/types.js";
import {
  FileTransferReceiver,
  FileTransferSender,
  FileTransferError,
} from "./transfer.js";

/** Default chunk size for the in-page demo (64 KiB). */
const DEMO_CHUNK_SIZE = 64 * 1024;

/** A monotonically increasing transfer id source for the demo. */
let nextTransferId = 1;

interface FileUiElements {
  readonly dropZone: HTMLElement;
  readonly fileInput: HTMLInputElement;
  readonly status: HTMLElement;
  readonly progressBar: HTMLElement;
  readonly integrity: HTMLElement;
}

type IntegrityState = "ok" | "failed" | "—";

const INTEGRITY_LABEL: Record<IntegrityState, string> = {
  ok: "integrity: OK ✓",
  failed: "integrity: FAILED ✗",
  "—": "integrity: —",
};

/** Query a required descendant of `host`, throwing (not silently casting) if it is absent. */
function hostEl<T extends HTMLElement>(host: HTMLElement, selector: string): T {
  const node = host.querySelector<T>(selector);
  if (node === null) {
    throw new Error(`file-transfer UI: missing element ${selector}`);
  }
  return node;
}

function setProgress(els: FileUiElements, fraction: number): void {
  const pct = Math.round(Math.max(0, Math.min(1, fraction)) * 100);
  els.progressBar.style.width = `${pct}%`;
  els.progressBar.textContent = `${pct}%`;
}

function setIntegrity(els: FileUiElements, state: IntegrityState): void {
  els.integrity.textContent = INTEGRITY_LABEL[state];
  els.integrity.dataset.state = state;
}

/**
 * Drive a single file through the in-process sender → receiver loop, updating the UI as chunks are
 * ingested. Resolves when the file is reassembled and its SHA-256 verified (or rejects on any
 * validation / integrity failure, which is surfaced in the status line).
 */
async function transferFile(
  bridge: ShBridge,
  els: FileUiElements,
  name: string,
  data: Uint8Array,
): Promise<void> {
  setIntegrity(els, "—");
  setProgress(els, 0);
  els.status.textContent = `offering ${name} (${data.length} bytes)…`;

  const transferId = nextTransferId++;
  const sender = await FileTransferSender.create(bridge, transferId, name, data, DEMO_CHUNK_SIZE);
  const { offerBytes } = sender.offer();

  // The receiver validates the offer exactly as the host would (name + cap + resume).
  const offer = bridge.decode_file_offer(offerBytes);
  const { receiver, resumeOffset } = FileTransferReceiver.accept(bridge, offer);
  sender.onAccept(resumeOffset);

  const initial = receiver.progress();
  els.status.textContent = `receiving ${initial.name}…`;
  setProgress(els, initial.fraction);

  // Stream framed chunks until the receiver reports the file is complete.
  for (let frame = sender.nextChunk(); frame !== null; frame = sender.nextChunk()) {
    const done = receiver.onChunk(frame);
    setProgress(els, receiver.progress().fraction);
    if (done) break;
  }

  // Verify integrity (whole-file SHA-256). Throws on mismatch.
  const verified = await receiver.finish();
  setIntegrity(els, "ok");
  els.status.textContent = `received ${receiver.name()} (${verified.length} bytes) — verified`;
  // Deliver the verified bytes as a browser download. Per the caller obligation documented in
  // transfer.ts, use ONLY the sanitized name (`receiver.name()`), never the raw offer name.
  // (OS-specific reserved-name filtering — e.g. Windows CON/NUL — is left to the browser's save UI.)
  deliverDownload(verified, receiver.name());
}

/** Offer `bytes` to the user as a download named `safeName` (already sanitized). */
function deliverDownload(bytes: Uint8Array, safeName: string): void {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = safeName;
  a.rel = "noopener";
  a.click();
  // Release the object URL on the next tick (after the click has initiated the download).
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** Read a dropped/selected `File` into a `Uint8Array`. */
async function readFile(file: File): Promise<Uint8Array> {
  return new Uint8Array(await file.arrayBuffer());
}

async function handleFiles(
  bridge: ShBridge,
  els: FileUiElements,
  files: FileList | null,
): Promise<void> {
  const file = files?.item(0);
  if (file === null || file === undefined) {
    return;
  }
  try {
    const data = await readFile(file);
    await transferFile(bridge, els, file.name, data);
  } catch (e: unknown) {
    setIntegrity(els, e instanceof FileTransferError ? "failed" : "—");
    els.status.textContent = e instanceof Error ? `failed: ${e.message}` : "failed";
  }
}

/**
 * Mount the file-transfer UI onto a host element, wiring the drag-and-drop + file-picker
 * affordances to the in-process transfer loop. Returns a disposer that removes the listeners.
 *
 * Idempotent on the listeners it installs; safe to call once during app startup.
 */
export function mountFileTransferUi(host: HTMLElement): () => void {
  host.innerHTML = `
    <div class="file-drop" id="file-drop" tabindex="0" role="button"
         aria-label="Drop a file here to send, or click to choose">
      Drop a file here to send (or click to choose)
      <input type="file" id="file-input" hidden />
    </div>
    <div class="file-status" id="file-status">idle</div>
    <div class="file-progress"><div class="file-progress-bar" id="file-progress-bar">0%</div></div>
    <div class="file-integrity" id="file-integrity" data-state="—">integrity: —</div>
  `;

  const els: FileUiElements = {
    dropZone: hostEl<HTMLElement>(host, "#file-drop"),
    fileInput: hostEl<HTMLInputElement>(host, "#file-input"),
    status: hostEl<HTMLElement>(host, "#file-status"),
    progressBar: hostEl<HTMLElement>(host, "#file-progress-bar"),
    integrity: hostEl<HTMLElement>(host, "#file-integrity"),
  };

  // The bridge is loaded once; the drop handler awaits it so the codec is always ready.
  const bridgePromise = loadBridge();

  const onDragOver = (e: DragEvent): void => {
    e.preventDefault();
    els.dropZone.classList.add("dragover");
  };
  const onDragLeave = (): void => {
    els.dropZone.classList.remove("dragover");
  };
  // Surface a wasm-bridge load failure in the status line instead of an unhandled rejection.
  const onBridgeError = (e: unknown): void => {
    els.status.textContent = e instanceof Error ? `failed: ${e.message}` : "failed";
  };
  const onDrop = (e: DragEvent): void => {
    e.preventDefault();
    els.dropZone.classList.remove("dragover");
    void bridgePromise
      .then((bridge) => handleFiles(bridge, els, e.dataTransfer?.files ?? null))
      .catch(onBridgeError);
  };
  const onPick = (): void => {
    void bridgePromise
      .then((bridge) => handleFiles(bridge, els, els.fileInput.files))
      .catch(onBridgeError);
  };
  const onClick = (): void => els.fileInput.click();

  els.dropZone.addEventListener("dragover", onDragOver);
  els.dropZone.addEventListener("dragleave", onDragLeave);
  els.dropZone.addEventListener("drop", onDrop);
  els.dropZone.addEventListener("click", onClick);
  els.fileInput.addEventListener("change", onPick);

  return () => {
    els.dropZone.removeEventListener("dragover", onDragOver);
    els.dropZone.removeEventListener("dragleave", onDragLeave);
    els.dropZone.removeEventListener("drop", onDrop);
    els.dropZone.removeEventListener("click", onClick);
    els.fileInput.removeEventListener("change", onPick);
  };
}
