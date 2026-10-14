// SecureShare: PeerJS connection + receiver-approved file transfer with AES-GCM encryption and ECDH key agreement.
// Demo note: key exchange is not authenticated by a trusted identity provider; compare fingerprints out-of-band.

const $ = (s) => document.querySelector(s);
const generateBtn = $("#generateBtn"), scanBtn = $("#scanBtn");
const pairingPanel = $("#pairingPanel"), panelTitle = $("#panelTitle"), panelDescription = $("#panelDescription");
const peerIdBox = $("#peerIdBox"), peerIdText = $("#peerIdText"), qrDemoWrap = $("#qrDemoWrap"), qrCanvas = $("#qrCanvas");
const pairCodeLabel = $("#pairCodeLabel"), pairCodeInput = $("#pairCodeInput"), qrScanNote = $("#qrScanNote");
const continueBtn = $("#continueBtn"), closePanelBtn = $("#closePanelBtn"), inlineFeedback = $("#inlineFeedback");
const startScanBtn = $("#startScanBtn"), stopScanBtn = $("#stopScanBtn"), qrReader = $("#qrReader"), copyIdBtn = $("#copyIdBtn");
const connectionPill = $("#connectionPill"), connectionMessage = $("#connectionMessage"), disconnectBtn = $("#disconnectBtn");
const headerStatus = $("#headerStatus"), headerStatusDot = $("#headerStatusDot");
const transferPanel = $("#transferPanel"), fileInput = $("#fileInput"), sendFileBtn = $("#sendFileBtn");
const incomingRequest = $("#incomingRequest"), incomingFileInfo = $("#incomingFileInfo");
const acceptFileBtn = $("#acceptFileBtn"), rejectFileBtn = $("#rejectFileBtn");
const progressWrap = $("#progressWrap"), transferStatus = $("#transferStatus"), transferProgress = $("#transferProgress");

let peer = null, dataConnection = null, qrScanner = null, peerReady = false;
let pendingIncoming = null, pendingOutgoing = null, receivedChunks = [], receivedBytes = 0;
let localEcdhKeys = null, localPublicKey = null, remotePublicKey = null, sessionAesKey = null, cryptoReady = false;
let incomingNonce = null, pendingRemoteJwk = null;
const CHUNK_SIZE = 16 * 1024;
const MAX_DEMO_FILE_SIZE = 20 * 1024 * 1024; // 20 MB demo cap
const cryptoStatus = document.createElement("p");
cryptoStatus.className = "inline-feedback"; cryptoStatus.id = "cryptoStatus"; cryptoStatus.textContent = "Encryption: waiting for connection";
$(".connection-status").appendChild(cryptoStatus);

function feedback(message) { inlineFeedback.textContent = message; }
function setConnectionState(state, message) {
  connectionPill.textContent = state;
  connectionPill.classList.toggle("connected", state === "Connected");
  connectionMessage.textContent = message;
  disconnectBtn.hidden = !peer;
  transferPanel.hidden = state !== "Connected";
}
function setHeaderState(ready) {
  headerStatus.textContent = ready ? "PEER SERVICE READY" : "CONNECTING SERVICE";
  headerStatusDot.classList.toggle("online", ready);
}
function drawQr(text) {
  qrCanvas.innerHTML = "";
  if (!window.QRCode) { qrCanvas.textContent = "QR library unavailable. Copy the Peer ID instead."; return; }
  new QRCode(qrCanvas, { text, width: 200, height: 200, colorDark: "#111827", colorLight: "#ffffff", correctLevel: QRCode.CorrectLevel.M });
}
async function stopCameraScanner() {
  if (qrScanner) {
    try { if (qrScanner.isScanning) await qrScanner.stop(); await qrScanner.clear(); } catch (_) {}
    qrScanner = null;
  }
  qrReader.hidden = true; stopScanBtn.hidden = true; startScanBtn.hidden = false;
}
function resetCryptoState() { localEcdhKeys = null; localPublicKey = null; remotePublicKey = null; sessionAesKey = null; cryptoReady = false; incomingNonce = null; if (cryptoStatus) cryptoStatus.textContent = "Encryption: waiting for connection"; }
function resetTransferUI() {
  pendingIncoming = null; pendingOutgoing = null; receivedChunks = []; receivedBytes = 0;
  incomingRequest.hidden = true; progressWrap.hidden = true;
  transferProgress.value = 0; sendFileBtn.disabled = false; acceptFileBtn.disabled = false;
}
function destroyPeer() {
  resetCryptoState();
  if (dataConnection) { try { dataConnection.close(); } catch (_) {} dataConnection = null; }
  if (peer) { try { peer.destroy(); } catch (_) {} peer = null; }
  peerReady = false; setHeaderState(false); resetTransferUI();
}
function openPanel(mode) {
  pairingPanel.hidden = false; feedback("");
  peerIdBox.hidden = true; qrDemoWrap.hidden = true; pairCodeLabel.hidden = true; pairCodeInput.hidden = true;
  qrScanNote.hidden = true; continueBtn.hidden = true; pairCodeInput.value = ""; qrCanvas.innerHTML = "";
  if (mode === "sender") {
    panelTitle.textContent = "Your sender Peer ID";
    panelDescription.textContent = "Keep this page open. Share this ID or its QR with the intended receiver.";
    peerIdBox.hidden = false; qrDemoWrap.hidden = false; createPeer();
  } else {
    panelTitle.textContent = "Connect to sender";
    panelDescription.textContent = "Enter or scan the Peer ID shown on the sender device.";
    pairCodeLabel.hidden = false; pairCodeInput.hidden = false; qrScanNote.hidden = false;
    continueBtn.hidden = false; continueBtn.textContent = "Connect to sender"; pairCodeInput.focus();
  }
  pairingPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}
function createPeer() {
  destroyPeer();
  if (!window.Peer) { feedback("PeerJS library did not load. Check internet and refresh."); return; }
  feedback("Connecting to PeerJS service…");
  setConnectionState("Waiting", "Creating a peer ID. Keep this tab open while the receiver connects.");
  peer = new Peer();
  peer.on("open", (id) => {
    peerReady = true; peerIdText.textContent = id; drawQr(id); setHeaderState(true);
    feedback("Peer ID ready. On the other device, choose “Start as receiver” and enter this ID.");
    setConnectionState("Waiting", "Peer ID is ready. Waiting for the receiver to connect.");
  });
  peer.on("connection", (connection) => {
    if (dataConnection && dataConnection.open) { connection.close(); feedback("A device is already connected. Disconnect it before accepting another connection."); return; }
    attachConnection(connection);
  });
  peer.on("disconnected", () => {
    peerReady = false; setHeaderState(false); feedback("Signalling connection lost. Trying to reconnect…");
    if (peer && !peer.destroyed) peer.reconnect();
  });
  peer.on("error", (error) => handlePeerError(error));
}
function connectToPeer() {
  const remoteId = pairCodeInput.value.trim();
  if (remoteId.length < 5) { feedback("Enter the complete Peer ID shown on the sender device."); return; }
  if (!window.Peer) { feedback("PeerJS library did not load. Check internet and refresh."); return; }
  destroyPeer(); feedback("Connecting to the sender…");
  setConnectionState("Connecting", "Trying to establish a peer-to-peer data connection. Keep both pages open.");
  peer = new Peer();
  peer.on("open", () => {
    peerReady = true; setHeaderState(true);
    dataConnection = peer.connect(remoteId, { reliable: true });
    attachConnection(dataConnection);
  });
  peer.on("disconnected", () => { setHeaderState(false); if (peer && !peer.destroyed) peer.reconnect(); });
  peer.on("error", handlePeerError);
}
function handlePeerError(error) {
  console.error("PeerJS error:", error);
  const map = {
    "peer-unavailable": "Sender not found. Verify the full Peer ID and keep the sender page open.",
    "network": "Network issue: check internet on both devices.",
    "server-error": "PeerJS signalling service error. Try again later.",
    "socket-error": "Could not reach PeerJS signalling service.",
    "unavailable-id": "Peer ID is already in use. Generate a new ID.",
    "browser-incompatible": "This browser does not support WebRTC."
  };
  feedback(map[error.type] || `Connection setup error (${error.type || "unknown"}). Check internet and try again.`);
}
async function initCrypto() {
  resetCryptoState();
  pendingRemoteJwk = null;
  sendFileBtn.disabled = true;
  if (!window.crypto || !crypto.subtle) {
    cryptoStatus.textContent = "Encryption unavailable: open this app through localhost/HTTPS.";
    feedback("Web Crypto API unavailable. Use Live Server or HTTPS.");
    return;
  }
  try {
    localEcdhKeys = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
    );
    localPublicKey = await crypto.subtle.exportKey("jwk", localEcdhKeys.publicKey);
    cryptoStatus.textContent = "Encryption: exchanging keys…";
    if (!sendMessage({ type: "crypto-key", key: localPublicKey })) {
      throw new Error("Could not send public key over the open data connection");
    }
    // A remote key can arrive while this device is still generating its key.
    if (pendingRemoteJwk) {
      const queued = pendingRemoteJwk;
      pendingRemoteJwk = null;
      await acceptRemotePublicKey(queued);
    }
  } catch (error) {
    console.error("[SecureShare] Crypto setup failed:", error);
    cryptoStatus.textContent = "Encryption setup failed — disconnect and reconnect";
    sendFileBtn.disabled = true;
    feedback("Could not initialize encryption. Check Console, then reconnect both devices.");
  }
}
async function acceptRemotePublicKey(jwk) {
  if (!localEcdhKeys || !localPublicKey) {
    pendingRemoteJwk = jwk;
    console.warn("[SecureShare] Remote crypto key arrived before local key was ready; queued.");
    return;
  }
  try {
    remotePublicKey = await crypto.subtle.importKey(
      "jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []
    );
    sessionAesKey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: remotePublicKey },
      localEcdhKeys.privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    const canonical = (key) => JSON.stringify({
      crv: key.crv, ext: key.ext, key_ops: key.key_ops, kty: key.kty,
      x: key.x, y: key.y
    });
    const pair = [canonical(localPublicKey), canonical(jwk)].sort();
    const digest = new Uint8Array(await crypto.subtle.digest(
      "SHA-256", new TextEncoder().encode(pair.join("|"))
    ));
    const fingerprint = Array.from(digest.slice(0, 8),
      b => b.toString(16).padStart(2, "0").toUpperCase()).join("");
    cryptoReady = true;
    cryptoStatus.textContent = `Encryption: AES-256-GCM active · compare fingerprint on BOTH devices: ${fingerprint}`;
    feedback("Encrypted session ready. Compare the fingerprint on both devices before sending files.");
    sendFileBtn.disabled = false;
    console.log("[SecureShare] Crypto handshake complete; fingerprint:", fingerprint);
  } catch (error) {
    console.error("[SecureShare] Key agreement failed:", error);
    cryptoReady = false;
    sessionAesKey = null;
    sendFileBtn.disabled = true;
    cryptoStatus.textContent = "Encryption: key agreement failed";
    feedback("Encryption handshake failed. Disconnect and reconnect both devices.");
  }
}
async function encryptFile(file) {
  const plain = await file.arrayBuffer();
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, sessionAesKey, plain);
  return { cipher, nonce: Array.from(nonce) };
}
async function decryptReceivedFile() {
  if (!pendingIncoming || !incomingNonce || !sessionAesKey) throw new Error("Missing decryption session data");
  const encrypted = new Uint8Array(receivedBytes);
  let offset = 0;
  for (const chunk of receivedChunks) { const part = new Uint8Array(chunk); encrypted.set(part, offset); offset += part.length; }
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(incomingNonce) }, sessionAesKey, encrypted);
  const blob = new Blob([plain], { type: pendingIncoming.mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a"); link.href = url; link.download = pendingIncoming.name; link.textContent = `Download decrypted ${pendingIncoming.name}`; link.className = "download-link"; link.id = "downloadReceivedFile";
  const oldLink = $("#downloadReceivedFile"); if (oldLink) oldLink.remove(); progressWrap.appendChild(link);
  transferProgress.value = 100; transferStatus.textContent = `Decrypted and received ${formatBytes(blob.size)}. Download the file below.`;
  sendMessage({ type: "file-complete" }); incomingRequest.hidden = true; pendingIncoming = null; receivedChunks = []; receivedBytes = 0; incomingNonce = null;
  feedback("File decrypted successfully. Tap the download link to save it.");
}

function attachConnection(connection) {
  console.log("[SecureShare] Attaching data connection to peer:", connection.peer);
  dataConnection = connection;
  connection.on("open", async () => {
    console.log("[SecureShare] Data connection opened with", connection.peer);
    feedback("Peer connection established. File requests are available below.");
    setConnectionState("Connected", `Connected to ${connection.peer}. Compare the encryption fingerprint before sending.`);
    await initCrypto();
  });
  connection.on("data", (data) => {
    try {
      Promise.resolve(handleIncomingData(data)).catch((error) => {
        console.error("[SecureShare] Incoming message handler failed:", error);
        feedback("Incoming message failed. Check Console and reconnect.");
      });
    } catch (error) {
      console.error("[SecureShare] Incoming message handler failed:", error);
      feedback("Incoming message failed. Check Console and reconnect.");
    }
  });
  connection.on("close", () => {
    console.warn("[SecureShare] Data connection closed with", connection.peer);
    dataConnection = null; resetTransferUI();
    setConnectionState("Disconnected", "The other device closed the connection. You can reconnect.");
  });
  connection.on("error", (error) => { console.error("[SecureShare] Data connection error:", error); feedback("Connection error. Try disconnecting and reconnecting."); });
}
function sendMessage(message) {
  if (!dataConnection || !dataConnection.open) {
    console.error("[SecureShare] Cannot send message: data connection is not open", { messageType: message?.type, connection: dataConnection });
    feedback("No active connection. Connect the devices first.");
    return false;
  }
  console.log("[SecureShare] Sending message:", message?.type, "to", dataConnection.peer);
  try {
    dataConnection.send(message);
    return true;
  } catch (error) {
    console.error("[SecureShare] dataConnection.send failed:", error);
    feedback("Could not send the request. Check Console for details.");
    return false;
  }
}
function handleIncomingData(data) {
  console.log("[SecureShare] Received data:", data);
  // Defensive compatibility: normalize JSON strings as well as PeerJS objects.
  if (typeof data === "string") {
    try { data = JSON.parse(data); } catch (_) {
      console.warn("[SecureShare] Ignoring non-JSON string data:", data);
      return;
    }
  }
  if (!data || typeof data !== "object") {
    console.warn("[SecureShare] Ignoring unsupported incoming data type:", typeof data);
    return;
  }
  if (!data.type) console.warn("[SecureShare] Incoming object has no message type:", data);
  if (data.type === "crypto-key") { acceptRemotePublicKey(data.key);
  } else if (data.type === "file-request") {
    if (!cryptoReady) { sendMessage({ type: "file-reject", reason: "Encrypted session is not ready. Reconnect and compare fingerprints." }); return; }
    if (!Number.isFinite(data.size) || data.size < 0 || data.size > MAX_DEMO_FILE_SIZE) {
      sendMessage({ type: "file-reject", reason: "This demo accepts files up to 20 MB." });
      feedback("Incoming file was rejected: demo limit is 20 MB."); return;
    }
    pendingIncoming = { name: String(data.name || "download.bin"), size: data.size, mime: String(data.mime || "application/octet-stream") };
    incomingFileInfo.textContent = `${pendingIncoming.name} · ${formatBytes(pendingIncoming.size)}. Accept only if you expected this file.`;
    incomingRequest.hidden = false; progressWrap.hidden = true;
    feedback("Incoming file request received. Accept or reject it below.");
  } else if (data.type === "file-accept") {
    if (!pendingOutgoing) return;
    transferStatus.textContent = "Sending file…"; progressWrap.hidden = false; sendFileBtn.disabled = true;
    sendFileChunks(pendingOutgoing).catch((error) => {
      console.error(error); transferStatus.textContent = "Transfer failed. Try a smaller file.";
      sendFileBtn.disabled = false; sendMessage({ type: "file-error", message: "Sender could not finish the transfer." });
    });
  } else if (data.type === "file-reject") {
    pendingOutgoing = null; sendFileBtn.disabled = false;
    transferStatus.textContent = data.reason || "Receiver rejected the request.";
    progressWrap.hidden = false; transferProgress.value = 0;
    feedback("Receiver rejected the file request.");
  } else if (data.type === "file-start") {
    if (!pendingIncoming) return;
    receivedChunks = []; receivedBytes = 0; incomingNonce = data.nonce; progressWrap.hidden = false; transferProgress.value = 0;
    transferStatus.textContent = `Receiving encrypted ${pendingIncoming.name}…`;
  } else if (data.type === "file-chunk") {
    if (!pendingIncoming || !(data.chunk instanceof ArrayBuffer || ArrayBuffer.isView(data.chunk))) return;
    const chunkBuffer = data.chunk instanceof ArrayBuffer ? data.chunk : data.chunk.buffer.slice(data.chunk.byteOffset, data.chunk.byteOffset + data.chunk.byteLength);
    receivedChunks.push(chunkBuffer); receivedBytes += chunkBuffer.byteLength;
    transferProgress.value = pendingIncoming.size ? Math.min(100, (receivedBytes / pendingIncoming.size) * 100) : 100;
    transferStatus.textContent = `Receiving… ${formatBytes(receivedBytes)} / ${formatBytes(pendingIncoming.size)}`;
  } else if (data.type === "file-end") {
    decryptReceivedFile().catch(error => { console.error("[SecureShare] Decryption failed:", error); transferStatus.textContent = "Decryption failed: file may be corrupted or keys differ."; feedback("Decryption failed. Reconnect both devices and verify the fingerprints match."); sendMessage({ type: "file-error", message: "Receiver could not decrypt the file." }); });
  } else if (data.type === "file-complete") {
    transferProgress.value = 100; transferStatus.textContent = "Transfer complete. Receiver has the file.";
    sendFileBtn.disabled = false; pendingOutgoing = null; feedback("File transfer completed.");
  } else if (data.type === "file-error") {
    transferStatus.textContent = data.message || "Transfer error."; sendFileBtn.disabled = false;
    feedback(data.message || "The other device reported a transfer error.");
  }
}
async function sendFileChunks(file) {
  if (!cryptoReady || !sessionAesKey) throw new Error("Encrypted session not ready");
  const encrypted = await encryptFile(file);
  const bytes = encrypted.cipher;
  sendMessage({ type: "file-start", name: file.name, size: file.size, encryptedSize: bytes.byteLength, nonce: encrypted.nonce });
  let offset = 0;
  while (offset < bytes.byteLength) {
    if (!dataConnection || !dataConnection.open) throw new Error("Connection closed");
    const chunk = bytes.slice(offset, Math.min(offset + CHUNK_SIZE, bytes.byteLength));
    dataConnection.send({ type: "file-chunk", chunk });
    offset += chunk.byteLength;
    transferProgress.value = bytes.byteLength ? Math.min(100, (offset / bytes.byteLength) * 100) : 100;
    transferStatus.textContent = `Sending encrypted data… ${formatBytes(offset)} / ${formatBytes(bytes.byteLength)}`;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  sendMessage({ type: "file-end" });
}
function finishReceive() {
  if (!pendingIncoming) return;
  const file = new Blob(receivedChunks, { type: pendingIncoming.mime });
  const url = URL.createObjectURL(file);
  const link = document.createElement("a");
  link.href = url; link.download = pendingIncoming.name; link.textContent = `Download ${pendingIncoming.name}`;
  link.className = "download-link";
  transferStatus.textContent = `Received ${formatBytes(file.size)}. Use the download link below to save it.`;
  const oldLink = $("#downloadReceivedFile");
  if (oldLink) oldLink.remove();
  link.id = "downloadReceivedFile";
  progressWrap.appendChild(link);
  transferProgress.value = 100;
  sendMessage({ type: "file-complete" });
  incomingRequest.hidden = true;
  pendingIncoming = null; receivedChunks = []; receivedBytes = 0;
  feedback("File received. Tap the download link to save it.");
}
function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "unknown size";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

generateBtn.addEventListener("click", () => openPanel("sender"));
scanBtn.addEventListener("click", () => openPanel("receiver"));
closePanelBtn.addEventListener("click", async () => { await stopCameraScanner(); pairingPanel.hidden = true; feedback(""); });
continueBtn.addEventListener("click", connectToPeer);
copyIdBtn.addEventListener("click", async () => {
  const id = peerIdText.textContent.trim(); if (!id) return;
  try { await navigator.clipboard.writeText(id); feedback("Peer ID copied. Paste it into the receiver device."); }
  catch (_) { feedback("Copy unavailable here. Select and copy the Peer ID manually."); }
});
disconnectBtn.addEventListener("click", async () => {
  await stopCameraScanner(); destroyPeer();
  setConnectionState("Disconnected", "Disconnected. Choose a role to start a new session.");
  disconnectBtn.hidden = true; feedback("Session disconnected.");
});
startScanBtn.addEventListener("click", async () => {
  if (!window.Html5Qrcode) { feedback("Scanner library did not load. Paste the Peer ID manually."); return; }
  qrReader.hidden = false; startScanBtn.hidden = true; stopScanBtn.hidden = false;
  try {
    qrScanner = new Html5Qrcode("qrReader");
    await qrScanner.start({ facingMode: "environment" }, { fps: 10, qrbox: { width: 220, height: 220 } },
      async (decodedText) => {
        const scanned = String(decodedText).trim();
        if (scanned.length >= 5 && scanned.length <= 120) {
          pairCodeInput.value = scanned; feedback("Peer ID QR scanned. Press “Connect to sender”."); await stopCameraScanner();
        } else feedback("QR contents do not look like a Peer ID.");
      }, () => {});
  } catch (error) {
    console.error(error); feedback("Could not start camera. Check permission and use HTTPS or localhost if required."); await stopCameraScanner();
  }
});
stopScanBtn.addEventListener("click", stopCameraScanner);

sendFileBtn.addEventListener("click", () => {
  const file = fileInput.files && fileInput.files[0];
  if (!file) { feedback("Choose a file first."); return; }
  if (file.size > MAX_DEMO_FILE_SIZE) { feedback("Choose a file smaller than 20 MB for this demo."); return; }
  if (!dataConnection || !dataConnection.open) { feedback("Connect the devices first."); return; }
  if (!cryptoReady || !sessionAesKey) { feedback("Wait until encrypted session is ready and compare the fingerprints on both devices."); return; }
  pendingOutgoing = file;
  transferProgress.value = 0; progressWrap.hidden = false;
  transferStatus.textContent = "Transfer request sent. Waiting for receiver approval…";
  console.log("[SecureShare] Requesting file transfer:", { name: file.name, size: file.size, peer: dataConnection.peer });
  sendFileBtn.disabled = true;
  if (!sendMessage({ type: "file-request", name: file.name, size: file.size, mime: file.type || "application/octet-stream" })) {
    pendingOutgoing = null; sendFileBtn.disabled = false;
  }
});
acceptFileBtn.addEventListener("click", () => {
  if (!pendingIncoming) return;
  sendMessage({ type: "file-accept" });
  incomingRequest.hidden = true;
  transferStatus.textContent = "Accepted. Waiting for file data…"; progressWrap.hidden = false;
  receivedChunks = []; receivedBytes = 0;
});
rejectFileBtn.addEventListener("click", () => {
  if (!pendingIncoming) return;
  sendMessage({ type: "file-reject", reason: "Receiver rejected the request." });
  pendingIncoming = null; incomingRequest.hidden = true;
  feedback("File request rejected. The peer connection remains open.");
});
window.addEventListener("beforeunload", () => {
  if (qrScanner && qrScanner.isScanning) qrScanner.stop().catch(() => {});
  if (peer) peer.destroy();
});
setConnectionState("Not connected", "Start as sender on one device and receiver on the other.");
setHeaderState(false);
