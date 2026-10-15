/**
 * VEIL CallManager (b144, W3): the device-side glue that turns the tested
 * calls.ts core (L1 signaling + state machine + integrity monitor) into a
 * live audio call on react-native-webrtc.
 *
 * ARCHITECTURE (design S3, docs/encrypted-calls-design.md):
 *  L1  call setup/ICE/end signals ride the session's PQ-hybrid ratchet
 *      envelopes (sendCallSignal) — the relay sees only cipher-text.
 *  L2  media travels DTLS-SRTP inside WebRTC (transport encryption).
 *  L3  per-call fresh AES-GCM frame key travels inside L1 (CallFrameCrypto)
 *      — wired for the data-channel media path; the W1 spike rides the
 *      standard media path first (see W4 notes in the design doc).
 *
 * PRIVACY: NO iceServers are configured for the spike — host candidates
 * only, so the two devices connect on the same LAN without leaking IPs to
 * any STUN/TURN provider. A disclosed third-party TURN arrives with W4,
 * and only then for calls that genuinely need relay.
 *
 * UI CONTRACT: CallManager is a module singleton. App configures it once
 * (relay/sessions/clientId closures), syncToken feeds it inbound signals,
 * CallOverlay subscribes to snapshots. No prop drilling, no navigation.
 */
import { Vibration } from 'react-native';
// b149: incoming-call ringtone. expo-av is already in the dev client (media
// playback uses it), so Metro hot-reload can reach the native module.
// Respects the hardware mute switch — silent mode stays silent (vibration
// still runs); we deliberately do NOT set playsInSilentMode.
import { Audio } from 'expo-av';
import ringAsset from '../../assets/veil-ring.wav';
import { RTCPeerConnection, RTCSessionDescription, RTCIceCandidate, mediaDevices, type MediaStream, type MediaStreamTrack } from 'react-native-webrtc';
import {
  type CallSignal, type CallState, CallIntegrityMonitor, CallRefusedError,
  newCallId, newCallSecretB64, processOffer, answerCall, endCall,
  extractDtlsFingerprint, sendCallSignal,
} from '../../vendor/device/src/calls';
import {
  encryptMessage, serializeRatchetState, deserializeRatchetState,
} from '../../vendor/crypto-core/src/index';

export type CallUiPhase = 'calling' | 'ringing' | 'connecting' | 'active' | 'ended';

export interface CallSnapshot {
  phase: CallUiPhase;
  role: 'caller' | 'callee';
  peerLabel: string;
  callId: string;
  startedAt: number | null;   // epoch ms, active only
  endedReason: string | null;
  muted: boolean;
  integrity: 'ok' | 'amber' | 'red';
}

interface CallSession {
  callId: string;
  token: string;
  peerLabel: string;
  role: 'caller' | 'callee';
  phase: CallUiPhase;
  core: CallState;                 // calls.ts state machine (guard rails)
  monitor: CallIntegrityMonitor;   // local-only interference log
  pc: RTCPeerConnection | null;
  local: MediaStream | null;
  pendingIce: CallSignal[];        // ICE that arrived before remote description
  pendingOfferSdp: string | null;  // callee: the offer SDP stashed until Answer
  startedAt: number | null;
  endedReason: string | null;
  muted: boolean;
  seq: number;
  ringVib: number | null;
  timeoutHandle: ReturnType<typeof setTimeout> | null;
}

interface CallTransport {
  relay: () => unknown;
  sessions: () => unknown;
  clientId: () => Promise<string | null>;
}

let transport: CallTransport | null = null;
let session: CallSession | null = null;
const listeners = new Set<(s: CallSnapshot | null) => void>();

const IDLE_CORE: CallState = { callId: '', phase: 'idle', offerFingerprint: null, l3SecretB64: null, seqSeen: -1 };

const RING_PATTERN = [0, 600, 800] as number[];

// b157 missed-call tracking: a call this device never answered leaves a
// durable trace, so an offer held out by the lock (hold-until-unlock keeps
// a locked phone holding no message data — call offers are ratcheted exactly
// like chat, so they cannot bypass the hold) still surfaces as a notice.
const locallyEndedCalls = new Set<string>();
const recordedMisses = new Set<string>();

function recordMissed(callId: string, token: string, peerLabel: string): void {
  if (recordedMisses.has(callId)) return;
  recordedMisses.add(callId);
  if (recordedMisses.size > 500) recordedMisses.clear();
  try { CallManager.onMissedCall?.(token, peerLabel); } catch { /* notice must never break calls */ }
}

// b149: looping ringtone for the ringing phase. Lazy-loaded on first use;
// any audio failure degrades to vibration-only (never blocks the call).
let ringSound: Awaited<ReturnType<typeof Audio.Sound.createAsync>>['sound'] | null = null;
let ringLoading: Promise<void> | null = null;
let ringBroken = false;

async function startRingtone(): Promise<void> {
  if (ringBroken) return;
  try {
    if (!ringSound && !ringLoading) {
      ringLoading = Audio.Sound.createAsync(ringAsset, { isLooping: true, volume: 1.0 }).then(({ sound }) => { // b198 (owner): full volume
        ringSound = sound;
      });
    }
    await ringLoading;
    await ringSound?.setIsLoopingAsync(true);
    await ringSound?.playAsync();
  } catch (e) {
    // Native module missing from this binary, or the asset failed to load:
    // disable for this run, keep calls working, vibration still alerts.
    ringBroken = true;
    console.warn('[veil-call] ringtone unavailable (vibration-only):', (e as Error)?.message ?? e);
  }
}

async function stopRingtone(): Promise<void> {
  try { await ringSound?.stopAsync(); } catch { /* already stopped */ }
}
const RINGOUT_MS = 45_000; // unanswered ring dies (both directions)
// b151 FIX (live-found, owner repro Oct 1): phase was flipping to 'active'
// the moment the answer SDP was sent/received — pure signaling, no proof
// the actual P2P media path ever connected. The owner saw native show
// "Integrity verified" + a running timer while the caller's side was still
// stuck "trying to connect": two peers disagreeing about whether a call
// was live. Phase now only becomes 'active' on pc.connectionState ===
// 'connected' (see wireConnectState below); if that never happens within
// this window, the call ends honestly instead of hanging in fake-active.
const CONNECT_TIMEOUT_MS = 25_000;

function snapshot(): CallSnapshot | null {
  if (!session) return null;
  return {
    phase: session.phase,
    role: session.role,
    peerLabel: session.peerLabel,
    callId: session.callId,
    startedAt: session.startedAt,
    endedReason: session.endedReason,
    muted: session.muted,
    integrity: session.monitor.status(),
  };
}

function notify(): void {
  const snap = snapshot();
  for (const l of listeners) l(snap);
}

// b146: pre-offer ICE buffer — 10s TTL, swept on each offer handling pass.
const preOfferIce = new Map<string, CallSignal[]>();
setInterval(() => {
  // candidates older than 10s without an offer are dead; the window is
  // bounded by the relay's fetch cadence anyway.
  preOfferIce.clear();
}, 10000).unref?.();

function clearRing(s: CallSession): void {
  void stopRingtone();
  if (s.ringVib !== null) { Vibration.cancel(); s.ringVib = null; }
  if (s.timeoutHandle !== null) { clearTimeout(s.timeoutHandle); s.timeoutHandle = null; }
}

/** Full teardown: keys, counters and monitor die with the call (design S3b.4). */
function teardown(s: CallSession, reason: string, sendEnd: boolean): void {
  locallyEndedCalls.add(s.callId); // b157: our own decline/clear must not later count as a missed call
  if (locallyEndedCalls.size > 500) locallyEndedCalls.clear();
  clearRing(s);
  try { s.monitor.destroy(); } catch { /* already destroyed */ }
  try { s.pc?.close(); } catch { /* already closed */ }
  s.local?.getTracks().forEach((t) => t.stop());
  s.pc = null;
  s.local = null;
  if (sendEnd && s.phase !== 'ended') {
    void signal(s.token, { __veil_call: 1, op: 'end', call_id: s.callId, reason });
  }
  s.phase = 'ended';
  s.endedReason = reason;
  s.core = endCall(s.core, reason);
  notify();
  // keep the ended snapshot on screen briefly, then fully clear
  setTimeout(() => { if (session && session.callId === s.callId && session.phase === 'ended') { session = null; notify(); } }, 2200);
}

async function signal(token: string, sig: CallSignal): Promise<void> {
  if (!transport) throw new Error('Call transport not configured yet.');
  const relay = transport.relay();
  const sessions = transport.sessions();
  const who = await transport.clientId();
  if (!relay || !sessions || !who) throw new Error('Session not ready.');
  await sendCallSignal(
    relay as never, sessions as never, token, who, sig,
    encryptMessage as never, serializeRatchetState as never, deserializeRatchetState as never,
  );
}

function armRingout(s: CallSession): void {
  s.timeoutHandle = setTimeout(() => {
    const wasRingingCallee = s.role === 'callee';
    teardown(s, s.role === 'caller' ? 'no answer' : 'missed', true);
    if (wasRingingCallee) recordMissed(s.callId, s.token, s.peerLabel); // b157
  }, RINGOUT_MS);
}

/** b151: signaling is done (answer sent/received) but the real media path
 *  hasn't connected yet — show it honestly and give it a bounded window. */
function armConnecting(s: CallSession): void {
  s.phase = 'connecting';
  if (s.timeoutHandle !== null) clearTimeout(s.timeoutHandle);
  s.timeoutHandle = setTimeout(() => {
    if (session === s && s.phase === 'connecting') {
      teardown(s, 'call failed to connect', true);
    }
  }, CONNECT_TIMEOUT_MS);
  notify();
}

/** b151: the ONLY place a call becomes 'active' — real transport proof,
 *  not just a signaling exchange. */
function markConnected(s: CallSession): void {
  if (s.phase !== 'connecting') return;
  if (s.timeoutHandle !== null) { clearTimeout(s.timeoutHandle); s.timeoutHandle = null; }
  s.phase = 'active';
  s.startedAt = Date.now();
  notify();
}

async function makePc(s: CallSession): Promise<RTCPeerConnection> {
  // NO iceServers (privacy note in the file header) — host candidates only.
  const pc = new RTCPeerConnection({ iceServers: [] });
  // rn-webrtc extends event-target-shim whose generics don't resolve under
  // bundler moduleResolution — the listeners are structurally sound at
  // runtime, so a narrow structural cast keeps tsc green without weakening
  // any other call on the PC surface.
  const pcEv = pc as unknown as {
    addEventListener(type: 'icecandidate', l: (e: { candidate: RTCIceCandidate | null }) => void): void;
    addEventListener(type: 'connectionstatechange', l: () => void): void;
  };
  pcEv.addEventListener('icecandidate', (e) => {
    if (!e.candidate) return; // null candidate = end-of-gathering
    const cand = JSON.stringify({ candidate: e.candidate.candidate, sdpMid: e.candidate.sdpMid ?? null, sdpMLineIndex: e.candidate.sdpMLineIndex ?? null });
    const send = () => signal(s.token, { __veil_call: 1, op: 'ice', call_id: s.callId, cand });
    // b196 (owner Metro log Oct 12: 429s dropped 4 of 9 ICE sends mid-call —
    // the LAN path survived on the ones that got through): one delayed retry
    // before dropping. A candidate 2.5s late is still comfortably inside the
    // gathering + connect window, and skips are silent call-quality losses.
    send().catch((err: Error) => {
      console.log(`[veil-call] ice send failed (${err.message}) — one retry in 2.5s`);
      setTimeout(() => {
        send().catch((err2: Error) => console.log(`[veil-call] ice send dropped after retry: ${err2.message}`));
      }, 2500);
    });
  });
  pcEv.addEventListener('connectionstatechange', () => {
    const st = pc.connectionState;
    // b151: this is the real signal — the only trustworthy "it's actually
    // live" event for either side (host-candidates-only means a same-LAN
    // path should connect fast; cross-network pairs correctly keep showing
    // "Connecting…" since there is genuinely no path without TURN yet).
    if (st === 'connected') { markConnected(s); return; }
    if (st === 'failed') {
      s.monitor.record('degraded', 'media path failed to establish');
      if (s.phase === 'connecting') { teardown(s, 'call failed to connect', true); return; }
      notify();
    }
    if (st === 'disconnected' && s.phase === 'active') { s.monitor.record('degraded', 'media path dropped mid-call'); notify(); }
  });
  return pc;
}

/** Attach the mic to the PC — addTrack (rn-webrtc has no addStream). */
function attachMic(pc: RTCPeerConnection, local: MediaStream): void {
  const track: MediaStreamTrack | undefined = local.getAudioTracks()[0];
  if (!track) throw new Error('No audio track from the microphone.');
  pc.addTrack(track, local);
}

async function captureMic(): Promise<MediaStream> {
  const stream = (await mediaDevices.getUserMedia({ audio: true, video: false })) as unknown as MediaStream;
  return stream;
}

export const CallManager = {
  /** App wires this once the session context exists (App.tsx). */
  configure(t: CallTransport): void { transport = t; },

  subscribe(l: (s: CallSnapshot | null) => void): () => void {
    listeners.add(l);
    l(snapshot());
    return () => { listeners.delete(l); };
  },

  snapshot,

  /** Caller path: start ringing out. */
  async start(token: string, peerLabel: string): Promise<void> {
    if (session && (session.phase === 'calling' || session.phase === 'ringing' || session.phase === 'connecting' || session.phase === 'active')) {
      throw new Error('A call is already in progress.');
    }
    const callId = newCallId();
    const s: CallSession = {
      callId, token, peerLabel, role: 'caller', phase: 'calling',
      core: { ...IDLE_CORE, callId }, monitor: new CallIntegrityMonitor(callId),
      pc: null, local: null, pendingIce: [], pendingOfferSdp: null, startedAt: null, endedReason: null,
      muted: false, seq: 1, ringVib: null, timeoutHandle: null,
    };
    session = s;
    notify();
    armRingout(s);
    try {
      s.local = await captureMic();
      const pc = await makePc(s);
      s.pc = pc;
      attachMic(pc, s.local);
      const offer = await pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: false });
      await pc.setLocalDescription(offer as never);
      await signal(token, {
        __veil_call: 1, op: 'offer', call_id: callId, seq: s.seq,
        sdp: (offer as unknown as { sdp: string }).sdp,
        k: newCallSecretB64(),
      });
      notify();
    } catch (e) {
      teardown(s, 'could not start the call', false);
      throw e;
    }
  },

  /** Callee accepted the ring. */
  async answer(): Promise<void> {
    const s = session;
    if (!s || s.phase !== 'ringing' || s.role !== 'callee') return;
    try {
      s.local = await captureMic();
      const pc = await makePc(s);
      s.pc = pc;
      attachMic(pc, s.local);
      const offer = s.pendingOfferSdp;
      if (!offer) throw new Error('No offer SDP for this call.');
      await pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: offer }) as never);
      // flush ICE that arrived before the remote description existed
      for (const ice of s.pendingIce) await addIce(pc, ice);
      s.pendingIce = [];
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer as never);
      s.core = answerCall(s.core);
      await signal(s.token, {
        __veil_call: 1, op: 'answer', call_id: s.callId, sdp: (answer as unknown as { sdp: string }).sdp,
      });
      clearRing(s);
      armConnecting(s);
    } catch (e) {
      console.log(`[veil-call] answer failed: ${(e as Error).message}`);
      teardown(s, 'call failed to connect', true);
    }
  },

  /** Callee declined. */
  decline(): void {
    const s = session;
    if (!s || s.phase !== 'ringing' || s.role !== 'callee') return;
    teardown(s, 'declined', true);
  },

  /** Either side hangs up. */
  hangup(): void {
    const s = session;
    if (!s || s.phase === 'ended') return;
    teardown(s, 'hangup', true);
  },

  /** b157: set by App — receives (threadToken, peerLabel) exactly once per
   *  missed call, and persists it into the thread's pending notices. */
  onMissedCall: null as ((threadToken: string, peerLabel: string) => void) | null,

  toggleMute(): void {
    const s = session;
    if (!s || s.phase !== 'active') return;
    s.muted = !s.muted;
    s.local?.getAudioTracks().forEach((t) => { t.enabled = !s.muted; });
    notify();
  },

  /** Entry point from syncToken: every call signal the sync decrypted.
   *  peerLabel (b152): the background sync path has no open thread UI to
   *  source a name from, so App passes the session row's title alongside. */
  async handleSignals(token: string, sigs: CallSignal[], peerLabel?: string): Promise<void> {
    // b157: a batch holding BOTH the offer and the caller's end for the same
    // call_id is a call that died before this device could ring (typically
    // the offer was held while the app was locked) — record the miss and
    // never ring a dead call.
    const ended = new Set(sigs.filter((x) => x.op === 'end').map((x) => x.call_id));
    for (const sig of sigs) {
      if (sig.op === 'offer' && ended.has(sig.call_id)) {
        recordMissed(sig.call_id, token, peerLabel ?? 'VEIL contact');
        continue;
      }
      await this.handleSignal(token, sig, peerLabel);
    }
  },

  async handleSignal(token: string, sig: CallSignal, peerLabel?: string): Promise<void> {
    const s = session;
    switch (sig.op) {
      case 'offer': {
        if (s && (s.phase === 'calling' || s.phase === 'connecting' || s.phase === 'active')) {
          // busy — refuse politely so the caller's UI clears fast
          await signal(token, { __veil_call: 1, op: 'end', call_id: sig.call_id, reason: 'busy' }).catch(() => undefined);
          return;
        }
        const core = s && s.callId === sig.call_id ? s.core : { ...IDLE_CORE, callId: sig.call_id };
        try {
          const next = processOffer(core, sig);
          const fresh: CallSession = {
            callId: sig.call_id, token, peerLabel: peerLabel ?? s?.peerLabel ?? 'VEIL contact',
            role: 'callee', phase: 'ringing', core: next,
            monitor: new CallIntegrityMonitor(sig.call_id),
            pc: null, local: null, pendingIce: [], pendingOfferSdp: sig.sdp ?? null,
            startedAt: null, endedReason: null, muted: false,
            seq: 0, ringVib: null, timeoutHandle: null,
          };
          session = fresh;
          // b146: drain any candidates that arrived before this offer
          const early = preOfferIce.get(sig.call_id);
          if (early) { fresh.pendingIce.push(...early); preOfferIce.delete(sig.call_id); }
          Vibration.vibrate(RING_PATTERN, true);
          void startRingtone();
          armRingout(fresh);
          notify();
        } catch (e) {
          if (e instanceof CallRefusedError) {
            console.log(`[veil-call] offer refused (${e.code}): replay/MITI guard did its job`);
          } else {
            console.log(`[veil-call] offer error: ${(e as Error).message}`);
          }
        }
        return;
      }
      case 'answer': {
        if (!s || s.callId !== sig.call_id || s.role !== 'caller' || s.phase !== 'calling') return;
        const fp = extractDtlsFingerprint(sig.sdp ?? '');
        if (!fp) { s.monitor.record('fingerprint', 'answer SDP carried no DTLS fingerprint — refusing'); teardown(s, 'call refused', true); return; }
        s.core = { ...s.core, offerFingerprint: fp };
        try {
          if (!s.pc) throw new Error('No peer connection.');
          await s.pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: sig.sdp as string }) as never);
          for (const ice of s.pendingIce) await addIce(s.pc, ice);
          s.pendingIce = [];
          clearRing(s);
          armConnecting(s);
        } catch (e) {
          console.log(`[veil-call] answer error: ${(e as Error).message}`);
          teardown(s, 'call failed to connect', true);
        }
        return;
      }
      case 'ice': {
        if (s && s.callId !== sig.call_id) return; // belongs to another call
        if (!s) {
          // b146: candidates can beat the offer across poll batches (the same
          // race the web client fixed). Buffer them per call and drain into
          // pendingIce the moment the offer creates the session — otherwise
          // the media path silently never connects.
          if (!sig.call_id) return;
          if (!preOfferIce.has(sig.call_id)) preOfferIce.set(sig.call_id, []);
          preOfferIce.get(sig.call_id)!.push(sig);
          if (preOfferIce.get(sig.call_id)!.length > 64) preOfferIce.get(sig.call_id)!.shift();
          return;
        }
        if (s.phase === 'ended') return;
        if (!s.pc || !(s.pc as unknown as { remoteDescription?: unknown }).remoteDescription) { s.pendingIce.push(sig); return; }
        try { await addIce(s.pc, sig); } catch (e) { console.log(`[veil-call] ice error: ${(e as Error).message}`); }
        return;
      }
      case 'end': {
        if (s && s.callId === sig.call_id) {
          // caller gave up while we were still ringing — a missed call
          const missedCandidate = s.role === 'callee' && s.phase === 'ringing' && !recordedMisses.has(sig.call_id);
          teardown(s, sig.reason ?? 'ended', false); // peer already sent their end
          if (missedCandidate) recordMissed(sig.call_id, token, s.peerLabel); // b157
          return;
        }
        // b157: end for a call this device never saw ring (offer held while
        // the app was locked). Our own decline/hangup already marked the
        // call locally-ended, so that echo never counts as a miss.
        if (!locallyEndedCalls.has(sig.call_id)) recordMissed(sig.call_id, token, peerLabel ?? 'VEIL contact');
        return;
      }
    }
  },
};

async function addIce(pc: RTCPeerConnection, sig: CallSignal): Promise<void> {
  if (!sig.cand) return;
  const c = JSON.parse(sig.cand) as { candidate: string; sdpMid?: string | null; sdpMLineIndex?: number | null };
  await pc.addIceCandidate(new RTCIceCandidate({
    candidate: c.candidate, sdpMid: c.sdpMid ?? undefined, sdpMLineIndex: c.sdpMLineIndex ?? undefined,
  }) as never);
}

