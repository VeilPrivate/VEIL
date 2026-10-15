import React, { memo, useEffect, useRef, useState } from 'react';
import { burnCountdownText } from '../burn';
import { ScrollView, View, Text, TextInput, TouchableOpacity, FlatList, StyleSheet, Platform, Image, Modal, ActivityIndicator } from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';
import { Video, ResizeMode } from 'expo-av';
import { Ionicons } from '@expo/vector-icons';

/** b140: above this size the pick preview shows a soft warning (send still allowed). */
const MEDIA_SOFT_WARN_BYTES = 26214400; // 25 MB — matches chat.ts MEDIA_SOFT_WARN_BYTES

export interface ChatMediaUI {
  name: string;
  mime: string;
  size: number;
  dl: boolean;
  /** render source: resolved decrypted data: URI, or the sender's local pick */
  src: string | null;
  loading: boolean;
  error: string | null;
}

export interface ChatMessageUI {
  id: string;
  text: string;
  mine: boolean;
  ts: string | null;
  media?: ChatMediaUI;
  read?: boolean;
  /** b62 groups: short sender label above the bubble (web parity) */
  sender?: string;
  /** b62 groups: per-sender Ed25519 signature verified against the roster */
  senderVerified?: boolean;
  /** b62 groups: centered system line (member joined / keys rotated / sig discard) */
  systemNote?: string;
  /** b72: epoch ms this message was first displayed here — burn-countdown anchor */
  openedAt?: number;
}

/** b62 groups: admin + roster context for group threads */
export interface ChatGroupInfoUI {
  isCreator: boolean;
  epoch: number;
  fingerprint: string | null;
  members: { veilId: string; nick?: string; ikPub: string; role: string; joinedEpoch: number; tag: string }[];
  busy: boolean;
  onRotate: () => Promise<void>;
  onEvict: (member: { veilId: string; ikPub: string }) => Promise<void>;
}

export interface PendingPick {
  uri: string;
  name: string;
  mime: string;
  size: number;
  /** b62: set when this pick is a recorded voice note (drives the preview UI) */
  voiceSeconds?: number;
}

export interface ChatScreenProps {
  title: string;
  subtitle: string;
  status: 'pending' | 'active' | 'ended';
  busy: boolean;
  error: string | null;
  /** b172: honest notice when history is not being saved on this device. */
  historyNotice?: string | null;
  messages: ChatMessageUI[];
  /** b179: thread session token — re-arms memoized rows on thread switches. */
  threadKey: string;
  /** b180: dismiss the transient error banner (App-level error state). */
  onDismissError: () => void;
  draft: string;
  onDraftChange: (t: string) => void;
  onSend: () => void;
  onBack: () => void;
  /** b144 W3: start an encrypted call on this thread (1:1, ready threads only) */
  onStartCall?: () => void;
  onEndSession: () => void;
  onAttach: () => void;
  pendingPick: PendingPick | null;
  onSendMedia: () => void;
  onCancelPick: () => void;
  allowDl: boolean;
  onAllowDlChange: (v: boolean) => void;
  onMediaRetry: (id: string) => void;
  onMediaSave: (id: string) => void;
  mediaSaving: Record<string, 'saving' | 'saved' | 'error'>;
  /** b62 voice notes */
  voiceRec: { active: boolean; seconds: number };
  onVoiceRecord: () => void;
  onVoiceCancel: () => void;
  onVoiceSend: () => void;
  /** web parity: true when the peer of THIS thread is a pinned contact —
   *  enables the 'New chat thread with the same person' header button */
  canNewThread: boolean;
  onNewThread: () => void;
  /** b155 decision A: contact (pinned) session — badge shows 'Pinned contact',
   *  no ceremony, no 'waiting for peer'. Trust comes from the pin. */
  contact?: boolean;
  /** per-session verify ceremony state (web parity: 'Verified for this session') */
  myVerified: boolean;
  peerVerified: boolean;
  /** b161 (parity handoff): resolves true only when the RELAY confirms our slot's
   *  verified flag — the panel stays open and shows an INLINE retry on false. */
  onVerifySession: () => Promise<boolean>;
  /** b126: session fingerprint — viewable in the panel pre AND post verification */
  sessionFingerprint?: string | null;
  /** b126: peer veil id (pairwise only) — gates the "Pin as contact" affordance */
  peerVeilId?: string | null;
  /** b126: peer already pinned — flips the panel button to "Pinned" */
  readOnly?: boolean;
  textOnly?: boolean;
  peerPinned?: boolean;
  /** b126: promote the session peer into the permanent contacts (pins table) */
  onPinContact?: () => void;
  /** b62 groups: present only on group threads */
  group?: ChatGroupInfoUI;
  /** b72 web parity: "burn N hours after open" countdown — set only when the
   *  session's burn-after-open dial is on; burnSeconds is the window. */
  burnAfterOpen?: boolean;
  burnSeconds?: number;
  /** b95 (owner-approved Sept 21): one-time dismissible "verify fingerprints"
   *  card on first open of an unverified pairwise thread. Non-blocking — the
   *  ceremony stays Signal-style; the card just surfaces it loudly once. */
  showVerifyCard?: boolean;
  onVerifyCardDismiss?: () => void;
  /** b123: rename this thread locally (chat sheet) — shown only when the
   *  peer veil-id is known. Name is device-local, never transmitted. */
  canRename?: boolean;
  threadNickname?: string | null;
  onRenameThread?: (name: string) => void;
}

function mediaCaption(m: ChatMediaUI): string {
  const mb = (m.size / 1048576).toFixed(1);
  return `${m.name || 'media'} · ${mb} MB${m.dl ? ' · saving allowed' : ''}`;
}

function fmtSecs(n: number): string {
  const m = Math.floor(n / 60), s = n % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

/**
 * b176: leaf burn-after-open countdown. Owns its own 1s interval so the
 * per-second re-render is confined to this Text node instead of re-rendering
 * every bubble in the FlatList (see b176 note above). Unmounted automatically
 * when burn-after-open is off or the row disappears.
 */
const BurnCountdown = memo(function BurnCountdown({ openedAt, burnSeconds }: { openedAt?: number; burnSeconds: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const iv = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(iv);
  }, []);
  return <Text> · {burnCountdownText(openedAt, burnSeconds, now)}</Text>;
});

/**
 * b179 (owner report Oct 2: "the txt is still shaking" — even after the
 * b176 countdown memo). ROOT CAUSE: App re-renders on EVERY keystroke
 * (draft lives in App state) and every sync/presence/unread poll, and the
 * uiMessages map built per render hands FlatList brand-new object
 * identities — so EVERY message row re-rendered on EVERY keystroke and
 * EVERY poll tick. On iOS that wholesale row re-render is visible as the
 * text jittering ("shaking"). Fix: the row is now its own memo component
 * with a VALUE comparator — it re-renders only when its own content
 * (text/timestamp/read-tick/media state) actually changes. Callbacks are
 * deliberately NOT compared: they're invoked on press, and presses always
 * re-render the row first via the state they flip. `threadKey` guards
 * against a stale closure surviving a thread switch (ChatScreen's instance
 * is reused across threads, so rows must re-arm when the token changes).
 */
interface MessageRowProps {
  item: ChatMessageUI;
  group?: ChatGroupInfoUI;
  burnAfterOpen?: boolean;
  burnSeconds?: number;
  threadKey: string;
  playing: boolean;
  avErrMsg: string | null;
  saveState?: 'saving' | 'saved' | 'error';
  onMediaRetry: (id: string) => void;
  onMediaSave: (id: string) => void;
  onToggleAudio: (id: string, src: string, mime: string) => void;
  onOpenLightbox: (src: string, name: string) => void;
  onOpenVideo: (src: string, name: string) => void;
}

const MessageRow = memo(function MessageRow({
  item, group, burnAfterOpen, burnSeconds, threadKey,
  playing, avErrMsg, saveState,
  onMediaRetry, onMediaSave, onToggleAudio, onOpenLightbox, onOpenVideo,
}: MessageRowProps) {
  const renderMedia = () => {
    const media = item.media!;
    if (media.loading && !media.src) {
      return (
        <View style={styles.mediaStub}>
          <ActivityIndicator color="#5fd4c4" size="small" />
          <Text style={styles.mediaStubTxt}>Decrypting media…</Text>
        </View>
      );
    }
    if (media.error && !media.src) {
      return (
        <TouchableOpacity style={styles.mediaStub} onPress={() => onMediaRetry(item.id)}>
          <Text style={styles.mediaErrTxt}>Couldn't load media — tap to retry</Text>
        </TouchableOpacity>
      );
    }
    if (media.src) {
      const isVideo = media.mime.startsWith('video/');
      const isAudio = media.mime.startsWith('audio/');
      // Audio (voice note): compact play row — no bubble image
      if (isAudio) {
        return (
          <View style={styles.audioRow}>
            <TouchableOpacity style={styles.audioBtn} onPress={() => onToggleAudio(item.id, media.src!, media.mime)}>
              <Text style={styles.audioBtnTxt}>{playing ? '⏸' : '▶'}</Text>
            </TouchableOpacity>
            <Text style={[styles.audioLbl, avErrMsg ? styles.mediaErrTxt : null]}>
              {avErrMsg ?? (playing ? 'Playing…' : 'Voice note')}
            </Text>
          </View>
        );
      }
      // Video: poster-style inline player
      if (isVideo) {
        return (
          <View>
            <TouchableOpacity activeOpacity={0.9} style={styles.videoBox} onPress={() => onOpenVideo(media.src!, media.name)}>
              <Text style={styles.videoIcon}>▶</Text>
              <Text style={styles.videoLbl}>Video — tap to play full screen</Text>
            </TouchableOpacity>
            {media.dl ? (
              <TouchableOpacity
                style={styles.saveBtn}
                onPress={() => onMediaSave(item.id)}
                disabled={saveState === 'saving' || saveState === 'saved'}
              >
                <Text style={styles.saveBtnTxt}>
                  {saveState === 'saving' ? 'Saving…' : saveState === 'saved' ? 'Saved ✓' : saveState === 'error' ? 'Save failed — tap to retry' : 'Save to Photos'}
                </Text>
              </TouchableOpacity>
            ) : null}
          </View>
        );
      }
      // Image (original path)
      return (
        <View>
          <TouchableOpacity activeOpacity={0.9} onPress={() => onOpenLightbox(media.src!, media.name)}>
            <Image source={{ uri: media.src }} style={styles.mediaImg} resizeMode="cover" />
          </TouchableOpacity>
          {media.dl ? (
            <TouchableOpacity
              style={styles.saveBtn}
              onPress={() => onMediaSave(item.id)}
              disabled={saveState === 'saving' || saveState === 'saved'}
            >
              <Text style={styles.saveBtnTxt}>
                {saveState === 'saving' ? 'Saving…' : saveState === 'saved' ? 'Saved ✓' : saveState === 'error' ? 'Save failed — tap to retry' : 'Save to Photos'}
              </Text>
            </TouchableOpacity>
          ) : null}
        </View>
      );
    }
    // b75: peer media that this device hasn't cached — a stub, never silence
    return (
      <TouchableOpacity style={styles.mediaStub} onPress={() => onMediaRetry(item.id)}>
        <Text style={styles.mediaStubTxt}>Tap to load media</Text>
      </TouchableOpacity>
    );
  };

  if (item.systemNote) {
    // b62 groups: centered system line (member joined / keys rotated /
    // signature discard) — same visual family as the capture notice
    return <Text style={styles.captureNotice}>{item.systemNote}</Text>;
  }
  if (item.text && item.text.startsWith('\u26a0')) {
    // b61: capture notice (screenshot/recording) — a centered system
    // line, not a chat bubble. Travels as a normal E2EE message so
    // web peers see the plain text too.
    return <Text style={styles.captureNotice}>{item.text}</Text>;
  }
  return (
    <View style={[styles.bubbleRow, item.mine ? styles.mineRow : styles.peerRow]}>
      <View style={[styles.bubble, item.mine ? styles.mineBubble : styles.peerBubble, item.media ? styles.mediaBubble : null]}>
        {group && !item.mine && item.sender ? (
          <Text style={styles.senderLbl}>
            {item.sender}{item.senderVerified ? ' ✓' : ''}
          </Text>
        ) : null}
        {item.media ? (
          <>
            {renderMedia()}
            <Text style={styles.mediaCaption}>{mediaCaption(item.media)}</Text>
          </>
        ) : (
          <Text style={item.mine ? styles.mineText : styles.peerText}>{item.text}</Text>
        )}
        {item.ts ? (
          <Text style={item.mine ? styles.mineTs : styles.peerTs}>
            {new Date(item.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            {/* b123: read-receipt tick — teal ✓ read, replacing the washed-out
                plain " · read" text (owner live-test ask, Sept 24). */}
            {item.mine && item.read ? <Text style={styles.readTick}>  ✓ read</Text> : null}
            {/* b198 two-dial: the SENDER's countdown only exists once the peer's
                read receipt landed (openedAt restamped at receipt) — pre-receipt
                there is no burn clock to show, matching the relay copy */}
            {burnAfterOpen && !item.systemNote && (!item.mine || item.read) ? <BurnCountdown openedAt={item.openedAt} burnSeconds={burnSeconds ?? 86400} /> : null}
          </Text>
        ) : null}
      </View>
    </View>
  );
}, (a, b) => {
  // VALUE compare — new object identities from the per-render map must NOT
  // re-render the row (that's the shake). Callbacks excluded by design.
  const ai = a.item, bi = b.item;
  if (ai.id !== bi.id || ai.text !== bi.text || ai.mine !== bi.mine || ai.ts !== bi.ts
    || ai.read !== bi.read || ai.sender !== bi.sender || ai.senderVerified !== bi.senderVerified
    || ai.systemNote !== bi.systemNote || ai.openedAt !== bi.openedAt) return false;
  const am = ai.media, bm = bi.media;
  if (!!am !== !!bm) return false;
  if (am && bm && (am.name !== bm.name || am.mime !== bm.mime || am.size !== bm.size
    || am.dl !== bm.dl || am.src !== bm.src || am.loading !== bm.loading || am.error !== bm.error)) return false;
  if (a.group !== b.group || a.burnAfterOpen !== b.burnAfterOpen || a.burnSeconds !== b.burnSeconds
    || a.threadKey !== b.threadKey || a.playing !== b.playing || a.avErrMsg !== b.avErrMsg
    || a.saveState !== b.saveState) return false;
  return true;
});

export function ChatScreen({ title, subtitle, status, busy, error, historyNotice, messages, threadKey, onDismissError, draft, onDraftChange, onSend, onBack, onStartCall, onEndSession, canNewThread, onNewThread, contact, myVerified, peerVerified, onVerifySession, onAttach, pendingPick, onSendMedia, onCancelPick, allowDl, onAllowDlChange, onMediaRetry, onMediaSave, mediaSaving, voiceRec, onVoiceRecord, onVoiceCancel, onVoiceSend, group, burnAfterOpen, burnSeconds, showVerifyCard, onVerifyCardDismiss, canRename, threadNickname, onRenameThread, sessionFingerprint, peerVeilId, peerPinned,
  readOnly, textOnly, onPinContact }: ChatScreenProps) {
  // b62 groups: Members overlay + evict two-tap arming
  const [groupPanel, setGroupPanel] = React.useState(false);
  const [evictArmed, setEvictArmed] = React.useState<string | null>(null);
  const [groupErr, setGroupErr] = React.useState<string | null>(null);
  React.useEffect(() => { if (!group) { setGroupPanel(false); setEvictArmed(null); setGroupErr(null); } }, [group]);

  // b111 (owner report: keyboard covers what you're typing): RN's
  // KeyboardAvoidingView "padding" mode proved unreliable on device — replaced
  // with deterministic keyboard-height padding: the composer grows by exactly
  // the keyboard height, the message list shrinks, and the input always sits
  // directly above the keys. Raw height comes from iOS's keyboardWillShow /
  // WillHide / WillChangeFrame (floating keyboard included).
  const kbH = useKbPadding();
  // follow the keyboard: once it's up, bring the newest message (and what
  // you're typing) into view — a small delay lets the shrunken list lay out.
  useEffect(() => {
    if (kbH > 0) { const t = setTimeout(() => listRef.current?.scrollToEnd?.({ animated: false }), 60); return () => clearTimeout(t); }
  }, [kbH]);
  // b180 (owner report: the "server is briefly busy" banner never goes away
  // unless you exit the thread): chat errors are TRANSIENT by design — the
  // banner says "wait a few seconds and try again", so it must hold itself
  // to that promise. Self-dismiss after 6s; a new error resets the clock,
  // a successful send clears it instantly (App: b180 success-path clear).
  useEffect(() => {
    if (!error) return;
    const t = setTimeout(() => onDismissError(), 6000);
    return () => clearTimeout(t);
  }, [error, onDismissError]);
  // b62: media playback (voice notes + video). One shared AV player: playing a
  // new item stops the previous. data: URIs work with expo-av via source={{ uri }}.
  const [audioPlayingId, setAudioPlayingId] = useState<string | null>(null);
  const soundRef = useRef<{ unloadAsync: () => Promise<unknown> } | null>(null);
  // b198 watchdog: expo-av's status callback proved unreliable as an end-of-
  // playback signal on real voice notes (owner: row stuck "Playing…" until a
  // manual pause — persisted across the didJustFinish + isPlaying callback
  // fixes). Poll the player DIRECTLY once a second: any loaded player that is
  // not playing past the start, or reports didJustFinish, is done. Cleared on
  // every stop, so it never outlives the playback.
  const audioWatchRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const stopAudio = async () => {
    if (audioWatchRef.current) { clearInterval(audioWatchRef.current); audioWatchRef.current = null; }
    if (soundRef.current) { try { await soundRef.current.unloadAsync(); } catch { /* already gone */ } soundRef.current = null; }
    setAudioPlayingId(null);
  };
  const [audioErr, setAudioErr] = useState<{ id: string; msg: string } | null>(null);
  const toggleAudio = async (id: string, src: string, mime: string) => {
    if (audioPlayingId === id) { await stopAudio(); return; }
    await stopAudio();
    setAudioErr(null);
    try {
      // b73 (owner report: receive-side voice notes viewable but silently
      // dead on tap): a prior recording session on this device leaves iOS's
      // audio session in .playAndRecord — reset it to plain playback first,
      // best-effort, so a stale record-mode session can't mute playback.
      const { Audio } = require('expo-av');
      try { await Audio.setAudioModeAsync({ allowsRecordingIOS: false, playsInSilentModeIOS: true, staysActiveInBackground: false }); } catch { /* best-effort */ }
      const { sound } = await Audio.Sound.createAsync(
        { uri: src },
        { shouldPlay: true },
        (st: { isLoaded?: boolean; didJustFinish?: boolean; isPlaying?: boolean; positionMillis?: number }) => {
          if (!st.isLoaded || st.didJustFinish) { console.log('[veil-av] status ended the playback — resetting row'); void stopAudio(); return; }
          if (st.isPlaying === false && (st.positionMillis ?? 0) > 0) { console.log('[veil-av] status stopped-without-finish — resetting row'); void stopAudio(); }
        },
      );
      soundRef.current = sound as unknown as { unloadAsync: () => Promise<unknown> };
      setAudioPlayingId(id);
      const watchdog = setInterval(async () => {
        try {
          const s = await (sound as unknown as { getStatusAsync: () => Promise<{ isLoaded?: boolean; didJustFinish?: boolean; isPlaying?: boolean; positionMillis?: number }> }).getStatusAsync();
          if (!s.isLoaded || s.didJustFinish || (s.isPlaying === false && (s.positionMillis ?? 0) > 0)) {
            console.log(`[veil-av] watchdog: playback ended (loaded=${!!s.isLoaded} finish=${!!s.didJustFinish} playing=${!!s.isPlaying} pos=${s.positionMillis ?? 0}) — resetting row`);
            void stopAudio();
          }
        } catch { void stopAudio(); }
      }, 1000);
      audioWatchRef.current = watchdog;
    } catch (e) {
      // b73: was silently swallowed — a dead ▶ with no feedback is exactly
      // the owner-reported symptom. Now visible + logged for Metro triage.
      console.log('[veil-av] playback failed:', String(e));
      // b74 (owner report: voice note SENT FROM WEB taps to "error"): the web
      // app records voice notes as audio/webm;codecs=opus (Chrome/Firefox
      // MediaRecorder) — iOS's AVPlayer CANNOT decode webm/opus at all, so
      // the tap fails no matter how clean the decrypt/cache was. Native-to-
      // native notes (.m4a) play fine. Real fix is web-side (WAV transcode
      // work order to builder); until it lands, say WHY instead of a generic
      // retry that can never succeed.
      const m = (mime || '').toLowerCase();
      if (m.includes('webm') || m.includes('ogg')) {
        setAudioErr({ id, msg: 'Web app voice notes use a codec iOS can\'t play — web fix in progress' });
      } else {
        setAudioErr({ id, msg: 'Could not play — tap to retry' });
      }
    }
  };
  useEffect(() => { return () => { void stopAudio(); }; }, []);
  const listRef = useRef<FlatList<ChatMessageUI>>(null);
  const [lightbox, setLightbox] = useState<{ src: string; name: string } | null>(null);
  // b140: full-screen video player — a video bubble taps straight into a
  // native-controls player covering the screen (voice notes keep the inline row).
  const [videoFS, setVideoFS] = useState<{ src: string; name: string } | null>(null);
  useEffect(() => {
    if (messages.length) listRef.current?.scrollToEnd?.({ animated: false });
  }, [messages.length]);

  // b163 (web P1.2 parity, owner decision Oct 2): sending requires BOTH sides'
  // fingerprint ceremony on EVERY pairwise path — pinned contact threads no
  // longer send on keys alone. Groups are exempt: their trust anchor is the
  // group signature scheme, not a pairwise ceremony.
  const verifyGate = !group && !(myVerified && peerVerified);
  const composerLocked = readOnly || status !== 'active' || busy || verifyGate;
  // b187: lounge read-only notice — the composer is locked by design; this
  // replaces any silence with the honest reason, styled as a soft system note.
  const loungeNote = readOnly
    ? 'Founder broadcast — only Matt posts here. Replies open when member groups land.'
    : (textOnly ? 'Founding testers forum — end-to-end encrypted. Photos and voice notes land in the next build.' : null);

  // (b66) the ✕ sheet is now VEIL-styled instead of the plain system action
  // sheet: End renders as a true RED destructive button (the system sheet showed
  // plain text on device), and a stray tap still can't end the session — End
  // requires a deliberate press on the red row.
  const [sheet, setSheet] = useState(false);
  // b126: verification panel replaces the system Alert — the fingerprint is
  // shown BEFORE "Mark verified" unlocks (two-step comparison gate), and the
  // same panel stays viewable any time AFTER verification via the badge.
  const [verifyPanel, setVerifyPanel] = useState<'ceremony' | 'view' | null>(null);
  /** b161: panel-LOCAL verify failure — never the app-wide error state (suppression rule). */
  const [verifyFail, setVerifyFail] = useState(false);
  const [compareArmed, setCompareArmed] = useState(false);
  // b123: local thread rename (device-local nickname against the peer veil-id)
  const [renameOpen, setRenameOpen] = useState(false);
  const [renameInput, setRenameInput] = useState('');
  // b176 (owner report Oct 2, live on-device: bubbles visibly "shaking"
  // side-to-side during rapid-fire bursts on a burn-after-open thread): the
  // b72 design ticked ONE parent-level clock state every second, which
  // re-rendered the ENTIRE message list 1×/s — stacked with per-message
  // renders from the burst it read as a continuous wobble. The tick now
  // lives inside <BurnCountdown> below, so a per-second update touches
  // only that one countdown Text node, and the FlatList renders only
  // when messages actually change.

  // b179: renderMedia moved into memoized MessageRow (shake fix) — see above.

  return (
    <View style={styles.fill}>
    <View style={styles.fill}>
      {/* header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={onBack} style={styles.backBtn}>
          <Text style={styles.backTxt}>‹ Back</Text>
        </TouchableOpacity>
        {onStartCall && status !== 'ended' && status !== 'pending' ? (
          <TouchableOpacity onPress={onStartCall} style={styles.callBtn} hitSlop={{ top: 10, bottom: 10, left: 6, right: 6 }}>
            {/* b198 (owner): a proper phone icon replaces the two-ring glyph */}
            <Ionicons name="call-outline" size={22} color="#7cf4c8" />
          </TouchableOpacity>
        ) : null}
        <View style={styles.headerMid}>
          <Text style={styles.title} numberOfLines={1}>{title}</Text>
          <Text style={styles.subtitle}>{status === 'pending' ? 'Waiting for your contact to accept…' : status === 'ended' ? 'Session ended' : subtitle}</Text>
          {group ? (
            <TouchableOpacity style={styles.vBadge} onPress={() => setGroupPanel(true)} hitSlop={{ top: 10, bottom: 10 }}>
              <Text style={styles.vBadgeTxtHalf}>Epoch {group.epoch} · Members</Text>
            </TouchableOpacity>
          ) : status !== 'ended' ? (
            /* b163 (web P1.2 parity): pinned contact threads show the SAME
             * ceremony state as invite threads — the 'Pinned contact' trust
             * chip is gone; sending unlocks only when both sides confirm.
             * The pin still anchors identity (panel shows the pinned state);
             * the ceremony is the human comparison on top of it. */
            <TouchableOpacity
              style={[styles.vBadge, myVerified && peerVerified ? styles.vBadgeOk : myVerified || peerVerified ? styles.vBadgeHalf : styles.vBadgeNone]}
              onPress={() => { setCompareArmed(false); setVerifyPanel(myVerified ? 'view' : 'ceremony'); }}
            >
              <Text style={[styles.vBadgeTxt, myVerified && peerVerified ? styles.vBadgeTxtOk : myVerified || peerVerified ? styles.vBadgeTxtHalf : styles.vBadgeTxtNone]}>
                {myVerified && peerVerified ? '✓ Verified' : myVerified ? 'You verified · waiting for peer' : peerVerified ? 'Peer verified · tap to verify' : 'Not verified'}
              </Text>
            </TouchableOpacity>
          ) : null}
        </View>
        {status !== 'ended' && canNewThread ? (
          <TouchableOpacity
            onPress={() => { if (!busy) onNewThread(); }}
            disabled={busy}
            style={styles.newThreadBtn}
            hitSlop={{ top: 8, bottom: 8, left: 4, right: 2 }}
            accessibilityLabel="Start a new thread with the same person"
          >
            <Text style={styles.newThreadTxt}>＋ New</Text>
          </TouchableOpacity>
        ) : null}
        {status !== 'ended' ? (
          <TouchableOpacity onPress={() => setSheet(true)} disabled={busy} style={styles.menuBtn} hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}>
            <Text style={styles.menuTxt}>✕</Text>
          </TouchableOpacity>
        ) : null}
      </View>

      {/* b62 groups: Members overlay — roster, epoch fingerprint, creator admin */}
      {group && groupPanel ? (
        <View style={styles.groupOverlay}>
          <View style={styles.groupPanel}>
            <View style={styles.groupPanelHead}>
              <Text style={styles.groupPanelTitle}>Group members</Text>
              <TouchableOpacity onPress={() => { setGroupPanel(false); setEvictArmed(null); setGroupErr(null); }} hitSlop={{ top: 10, bottom: 10 }}>
                <Text style={styles.groupCloseTxt}>✕</Text>
              </TouchableOpacity>
            </View>
            <Text style={styles.groupFp}>
              Epoch {group.epoch} fingerprint{'\n'}
              {group.fingerprint || 'Not available yet — opens with the group'}
            </Text>
            <ScrollView style={styles.groupMemberList}>
              {group.members.length === 0 ? (
                <Text style={styles.groupEmpty}>The roster opens with the group.</Text>
              ) : group.members.map((m) => (
                <View key={m.veilId} style={styles.groupMemberRow}>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.groupMemberName}>{m.nick ? m.nick : m.veilId.slice(0, 10) + '…'}</Text>
                    {!!m.nick && <Text style={styles.groupMemberMeta}>{m.veilId.slice(0, 10)}…</Text>}
                    <Text style={styles.groupMemberMeta}>{m.role === 'creator' ? 'Creator' : 'Member'} · joined epoch {m.joinedEpoch}</Text>
                  </View>
                  {group.isCreator ? (
                    <TouchableOpacity
                      style={[styles.evictBtn, evictArmed === m.veilId ? styles.evictBtnArmed : null]}
                      disabled={group.busy || m.role === 'creator'}
                      onPress={async () => {
                        if (evictArmed !== m.veilId) { setEvictArmed(m.veilId); setTimeout(() => setEvictArmed((cur) => (cur === m.veilId ? null : cur)), 6000); return; }
                        setEvictArmed(null); setGroupErr(null);
                        try { await group.onEvict({ veilId: m.veilId, ikPub: m.ikPub }); } catch (e) { setGroupErr('That did not work — please try again.'); console.log('[veil-error] group-evict:', String((e as Error).message ?? e)); }
                      }}
                    >
                      <Text style={styles.evictBtnTxt}>{evictArmed === m.veilId ? 'Remove?' : 'Remove'}</Text>
                    </TouchableOpacity>
                  ) : null}
                </View>
              ))}
            </ScrollView>
            {group.isCreator ? (
              <TouchableOpacity
                style={styles.rotateBtn}
                disabled={group.busy}
                onPress={async () => {
                  setGroupErr(null);
                  try { await group.onRotate(); } catch (e) { setGroupErr('That did not work — please try again.'); console.log('[veil-error] group-evict:', String((e as Error).message ?? e)); }
                }}
              >
                <Text style={styles.rotateBtnTxt}>{group.busy ? 'Working…' : 'Rotate keys now'}</Text>
              </TouchableOpacity>
            ) : null}
            {groupErr ? <Text style={styles.groupErr}>{groupErr}</Text> : null}
          </View>
        </View>
      ) : null}

      {error ? <Text style={styles.error}>{error}</Text> : null}

      {historyNotice ? <Text style={styles.notice}>{historyNotice}</Text> : null}

      {showVerifyCard && !myVerified ? (
        <View style={styles.vCard}>
          <View style={styles.vCardBody}>
            <Text style={styles.vCardTitle}>Verify this session</Text>
            <Text style={styles.vCardTxt}>Sending unlocks once you both compare the verification code out-of-band (call them or meet) and confirm it. This is a security check against interception on every chat path.</Text>
            <View style={styles.vCardRow}>
              <TouchableOpacity style={styles.vCardBtn} onPress={() => { setCompareArmed(false); setVerifyFail(false); setVerifyPanel('ceremony'); }} accessibilityLabel="Verify fingerprints now">
                <Text style={styles.vCardBtnTxt}>Verify fingerprints</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.vCardSkip} onPress={onVerifyCardDismiss} accessibilityLabel="Dismiss verification reminder">
                <Text style={styles.vCardSkipTxt}>Not now</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      ) : null}

      {/* messages */}
      <FlatList
        ref={listRef}
        style={styles.list}
        keyboardShouldPersistTaps="handled"
        data={messages}
        keyExtractor={(m) => m.id}
        renderItem={({ item }) => (
          <MessageRow
            item={item}
            group={group}
            burnAfterOpen={burnAfterOpen}
            burnSeconds={burnSeconds}
            threadKey={threadKey}
            playing={audioPlayingId === item.id}
            avErrMsg={audioErr?.id === item.id ? audioErr.msg : null}
            saveState={mediaSaving[item.id]}
            onMediaRetry={onMediaRetry}
            onMediaSave={onMediaSave}
            onToggleAudio={toggleAudio}
            onOpenLightbox={(s, n) => setLightbox({ src: s, name: n })}
            onOpenVideo={(s, n) => { stopAudio(); setVideoFS({ src: s, name: n }); }}
          />
        )}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyTxt}>{status === 'pending' ? 'Your contact hasn\u2019t accepted yet — messages will flow once they do.' : 'No messages yet. Say hi.'}</Text>
          </View>
        }
      />

      {/* composer */}
      <View style={[styles.composer, kbH > 0 && { paddingBottom: kbH + 12 }]}>
        {verifyGate && status === 'active' && !busy ? (
          /* b163 (web P1.2 parity): blocked-send state explains itself and the
           * ceremony stays reachable from the composer — no dead-end lock. */
          <View style={styles.verifyNotice}>
            <Text style={styles.verifyNoticeTxt}>🔒 Sending unlocks once you both compare the verification code and confirm it.</Text>
            <TouchableOpacity
              style={styles.verifyNowBtn}
              onPress={() => { setCompareArmed(false); setVerifyFail(false); setVerifyPanel(myVerified ? 'view' : 'ceremony'); }}
              accessibilityLabel="Verify now"
            >
              <Text style={styles.verifyNowBtnTxt}>Verify now</Text>
            </TouchableOpacity>
          </View>
        ) : null}
        {loungeNote ? (
          <Text style={styles.loungeNoteTxt}>{loungeNote}</Text>
        ) : null}
        <TextInput
          style={[styles.input, composerLocked && styles.inputLocked]}
          placeholder={readOnly ? 'Read-only founder broadcast' : status === 'pending' ? 'Locked until your contact accepts' : verifyGate ? 'Locked until you both verify' : 'Message…'}
          placeholderTextColor="#3a4750"
          value={draft}
          onChangeText={onDraftChange}
          editable={!composerLocked}
          multiline
        />
        <TouchableOpacity
          style={[styles.attachBtn, textOnly ? styles.attachBtnOff : (composerLocked ? styles.attachBtnOff : styles.attachBtnOn)]}
          disabled={composerLocked || !!textOnly}
          onPress={onAttach}
        >
          <Text style={[styles.attachTxt, composerLocked && styles.attachTxtOff]}>＋</Text>
        </TouchableOpacity>
        {/* b62 voice notes: mic in the composer; recording UI replaces the bar */}
        {voiceRec.active ? (
          <TouchableOpacity style={styles.micBtnRec} onPress={onVoiceSend}>
            <Text style={styles.micBtnTxt}>● {fmtSecs(voiceRec.seconds)} — send</Text>
          </TouchableOpacity>
        ) : (
          <TouchableOpacity
            style={[styles.attachBtn, textOnly ? styles.attachBtnOff : (composerLocked ? styles.attachBtnOff : styles.attachBtnOn)]}
            disabled={composerLocked || !!textOnly}
            onPress={onVoiceRecord}
          >
            <Text style={[styles.attachTxt, composerLocked && styles.attachTxtOff]}>🎤</Text>
          </TouchableOpacity>
        )}
        {voiceRec.active ? (
          <TouchableOpacity style={[styles.sendBtn, styles.sendBtnOff]} onPress={onVoiceCancel}>
            <Text style={styles.sendTxt}>✕</Text>
          </TouchableOpacity>
        ) : (
          <TouchableOpacity
            style={[styles.sendBtn, (!composerLocked && draft.trim()) ? styles.sendBtnOn : styles.sendBtnOff]}
            disabled={composerLocked || !draft.trim()}
            onPress={onSend}
          >
            <Text style={[styles.sendTxt, (!composerLocked && draft.trim()) && styles.sendTxtOn]}>Send</Text>
          </TouchableOpacity>
        )}
      </View>
    </View>

      {/* attach confirm — web parity: preview + Cancel/Send before anything is encrypted.
          Rendered as a plain in-screen overlay, NOT React Native's <Modal>. The photo
          picker (ImagePicker.launchImageLibraryAsync) itself presents a native iOS modal
          (PHPickerViewController); opening a SECOND native modal (RN's <Modal>) the instant
          it resolves collides with iOS's dismiss animation and freezes the whole screen
          (build 25 bug — looked like a total hang, no scroll/back). A plain absolutely
          positioned View has no native presentation of its own, so there's nothing to
          collide with. Kept OUTSIDE the KeyboardAvoidingView (build 26 bug: 'padding'
          behavior pads the AvoidingView's own box when the keyboard is up, which pushes
          this absolutely-positioned overlay's bottom edge off-screen behind the keyboard,
          clipping Cancel/Send — being outside means it's always anchored to the real
          screen bounds regardless of keyboard state; handleAttach also dismisses the
          keyboard proactively as a belt-and-suspenders fix). */}
      {pendingPick ? (
        <View style={styles.pickOverlay} pointerEvents="auto">
          <View style={styles.pickSheet}>
            {pendingPick.voiceSeconds ? (
              <>
                <Text style={styles.pickTitle}>Send this voice note?</Text>
                <View style={styles.pickAudioPreview}>
                  <Text style={styles.pickAudioIcon}>🎤</Text>
                  <Text style={styles.pickAudioMeta}>{fmtSecs(pendingPick.voiceSeconds)} · encrypted end-to-end before upload</Text>
                </View>
              </>
            ) : pendingPick.mime.startsWith('video/') ? (
              <>
                <Text style={styles.pickTitle}>Send this video?</Text>
                <View style={styles.pickAudioPreview}>
                  <Text style={styles.pickAudioIcon}>▶</Text>
                  <Text style={styles.pickAudioMeta}>{pendingPick.name || 'video'}</Text>
                </View>
                <Text style={styles.pickMeta}>{(pendingPick.size / 1048576).toFixed(1)} MB · encrypted on this phone before it is uploaded</Text>
                {pendingPick.size > MEDIA_SOFT_WARN_BYTES ? <Text style={styles.pickWarn}>Large file — encrypting and sending may take a few minutes. Keep VEIL open until it sends.</Text> : null}
              </>
            ) : (
              <>
                <Text style={styles.pickTitle}>Send this image?</Text>
                <Image source={{ uri: pendingPick.uri }} style={styles.pickPreview} resizeMode="contain" />
                <Text style={styles.pickMeta}>{pendingPick.name || 'media'}</Text>
                <Text style={styles.pickMeta}>{(pendingPick.size / 1048576).toFixed(1)} MB · encrypted on this phone before it is uploaded</Text>
                {pendingPick.size > MEDIA_SOFT_WARN_BYTES ? <Text style={styles.pickWarn}>Large file — encrypting and sending may take a few minutes. Keep VEIL open until it sends.</Text> : null}
              </>
            )}
            <TouchableOpacity style={styles.dlToggle} onPress={() => onAllowDlChange(!allowDl)} activeOpacity={0.7}>
              <View style={[styles.dlBox, allowDl && styles.dlBoxOn]}>
                {allowDl ? <Text style={styles.dlBoxTxt}>✓</Text> : null}
              </View>
              <Text style={styles.dlToggleTxt}>Allow recipient to save this {pendingPick.voiceSeconds ? 'voice note' : pendingPick.mime.startsWith('video/') ? 'video' : 'image'}</Text>
            </TouchableOpacity>
            <View style={styles.pickBtns}>
              <TouchableOpacity style={styles.pickCancel} onPress={onCancelPick}>
                <Text style={styles.pickCancelTxt}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.pickSend} onPress={onSendMedia} disabled={busy}>
                <Text style={styles.pickSendTxt}>{busy ? 'Sending…' : 'Send'}</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      ) : null}

      {/* lightbox — full-screen media view */}
      {/* (b66) VEIL-styled ✕ sheet — End is a real red destructive button */}
      <Modal visible={sheet} transparent animationType="slide" onRequestClose={() => setSheet(false)}>
        <TouchableOpacity style={styles.sheetBackdrop} activeOpacity={1} onPress={() => setSheet(false)}>
          <TouchableOpacity style={styles.sheetPanel} activeOpacity={1} onPress={() => undefined}>
            {canRename && onRenameThread ? (
              <TouchableOpacity style={styles.sheetRow} onPress={() => { setSheet(false); setRenameInput(threadNickname ?? ''); setRenameOpen(true); }}>
                <Text style={styles.sheetRowTxt}>Rename this thread</Text>
                <Text style={styles.sheetRowSub}>Device-local only — never transmitted, never synced</Text>
              </TouchableOpacity>
            ) : null}
            {canNewThread ? (
              <TouchableOpacity style={styles.sheetRow} onPress={() => { setSheet(false); onNewThread(); }}>
                <Text style={styles.sheetRowTxt}>New chat thread with the same person</Text>
                <Text style={styles.sheetRowSub}>All-new keys — no new invitation needed</Text>
              </TouchableOpacity>
            ) : null}
            <TouchableOpacity style={styles.sheetRowDanger} onPress={() => { setSheet(false); onEndSession(); }}>
              {group ? (
                <>
                  <Text style={styles.sheetRowDangerTxt}>Delete this group thread</Text>
                  <Text style={styles.sheetRowDangerSub}>Removes the thread from this device</Text>
                </>
              ) : (
                <>
                  <Text style={styles.sheetRowDangerTxt}>End this session</Text>
                  <Text style={styles.sheetRowDangerSub}>Ends it on both sides — permanently</Text>
                </>
              )}
            </TouchableOpacity>
            <TouchableOpacity style={styles.sheetRowCancel} onPress={() => setSheet(false)}>
              <Text style={styles.sheetCancelTxt}>Cancel</Text>
            </TouchableOpacity>
          </TouchableOpacity>
        </TouchableOpacity>
      </Modal>
      {/* b126 verification panel — fingerprint viewable pre AND post verification;
          "Mark verified" only unlocks after an explicit out-of-band comparison
          confirmation. VEIL-themed per standing rule (#101920 card, #7cf4c8 accent). */}
      <Modal visible={!!verifyPanel} transparent animationType="fade" onRequestClose={() => setVerifyPanel(null)}>
        <TouchableOpacity style={styles.rnBackdrop} activeOpacity={1} onPress={() => setVerifyPanel(null)}>
          <TouchableOpacity style={styles.rnCard} activeOpacity={1} onPress={() => undefined}>
            {verifyPanel === 'ceremony' ? (
              <>
                <Text style={styles.rnTitle}>Verify this session</Text>
                <Text style={styles.fpBox} selectable>
                  {sessionFingerprint ?? '(fingerprint unavailable on this device — compare the fingerprint shown on your peer\'s screen)'}
                </Text>
                <Text style={styles.rnBody}>Compare it with your peer out-of-band — read it to them on a call, or side by side in person. Only continue if every group of characters matches exactly.</Text>
                <TouchableOpacity
                  style={[styles.fpStepBtn, compareArmed && styles.fpStepBtnOn]}
                  onPress={() => setCompareArmed(true)}
                  disabled={compareArmed}
                >
                  <Text style={[styles.fpStepBtnTxt, compareArmed && styles.fpStepBtnTxtOn]}>
                    {compareArmed ? '✓ Compared — they match' : 'I compared them — they match'}
                  </Text>
                </TouchableOpacity>
                {verifyPanel === 'ceremony' && verifyFail ? (
                  <Text style={styles.fpFailTxt}>Verification failed to save — tap to retry.</Text>
                ) : null}
                <View style={styles.rnActions}>
                  <TouchableOpacity style={styles.rnBtnGhost} onPress={() => setVerifyPanel(null)}>
                    <Text style={styles.rnBtnGhostTxt}>Cancel</Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={[styles.rnBtnTeal, !compareArmed && styles.fpBtnDisabled]}
                    disabled={!compareArmed}
                    onPress={() => {
                      setVerifyFail(false);
                      void onVerifySession().then((ok) => { if (!ok) setVerifyFail(true); else setVerifyPanel(null); });
                    }}
                  >
                    <Text style={styles.rnBtnTealTxt}>{verifyFail ? 'Retry' : 'Mark verified'}</Text>
                  </TouchableOpacity>
                </View>
              </>
            ) : verifyPanel === 'view' ? (
              <>
                <Text style={styles.rnTitle}>Session fingerprint</Text>
                <Text style={styles.fpBox} selectable>
                  {sessionFingerprint ?? '(fingerprint unavailable on this device)'}
                </Text>
                <Text style={styles.fpStatus}>
                  You verified this session ✓{'\n'}{peerVerified ? 'Peer verified this session ✓' : 'Peer has not verified yet'}
                </Text>
                {peerVeilId ? (
                  peerPinned ? (
                    <Text style={styles.fpPinned}>✓ Pinned in contacts</Text>
                  ) : (
                    <TouchableOpacity style={styles.rnBtnTeal} onPress={() => onPinContact?.()}>
                      <Text style={styles.rnBtnTealTxt}>Pin as contact</Text>
                    </TouchableOpacity>
                  )
                ) : null}
                <View style={styles.rnActions}>
                  <TouchableOpacity style={styles.rnBtnGhost} onPress={() => setVerifyPanel(null)}>
                    <Text style={styles.rnBtnGhostTxt}>Close</Text>
                  </TouchableOpacity>
                </View>
              </>
            ) : null}
          </TouchableOpacity>
        </TouchableOpacity>
      </Modal>
      {/* b123: rename modal — same VEIL modal pattern as the Contacts nickname */}
      <Modal visible={renameOpen} transparent animationType="fade" onRequestClose={() => setRenameOpen(false)}>
        <TouchableOpacity style={styles.rnBackdrop} activeOpacity={1} onPress={() => setRenameOpen(false)}>
          <TouchableOpacity style={styles.rnCard} activeOpacity={1} onPress={() => undefined}>
            <Text style={styles.rnTitle}>Rename this thread</Text>
            <Text style={styles.rnBody}>Stored on this device only. Never transmitted, never synced, never on the server.</Text>
            <TextInput
              style={styles.rnInput}
              placeholder="e.g. Founder Tester Lounge"
              placeholderTextColor="#3b4b56"
              value={renameInput}
              onChangeText={setRenameInput}
              maxLength={40}
            />
            <View style={styles.rnActions}>
              <TouchableOpacity style={styles.rnBtnGhost} onPress={() => setRenameOpen(false)}>
                <Text style={styles.rnBtnGhostTxt}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.rnBtnTeal}
                onPress={() => { setRenameOpen(false); onRenameThread?.(renameInput.trim()); }}
              >
                <Text style={styles.rnBtnTealTxt}>Save</Text>
              </TouchableOpacity>
            </View>
          </TouchableOpacity>
        </TouchableOpacity>
      </Modal>
      <Modal visible={!!videoFS} animationType="fade" onRequestClose={() => setVideoFS(null)} supportedOrientations={['portrait', 'landscape', 'landscape-left', 'landscape-right']}>
        {videoFS ? (
          <View style={styles.videoFSBg}>
            <Video
              source={{ uri: videoFS.src }}
              style={styles.videoFSPlayer}
              useNativeControls
              shouldPlay
              resizeMode={ResizeMode.CONTAIN}
              onError={() => setVideoFS(null)}
            />
            <TouchableOpacity style={styles.videoFSClose} onPress={() => setVideoFS(null)}>
              <Text style={styles.videoFSCloseTxt}>✕</Text>
            </TouchableOpacity>
            <Text style={styles.videoFSHint}>{videoFS.name} — decrypted on this phone</Text>
          </View>
        ) : null}
      </Modal>
      <Modal visible={!!lightbox} transparent animationType="fade" onRequestClose={() => setLightbox(null)}>
        <TouchableOpacity style={styles.lightbox} activeOpacity={1} onPress={() => setLightbox(null)}>
          {lightbox ? <Image source={{ uri: lightbox.src }} style={styles.lightboxImg} resizeMode="contain" /> : null}
          <Text style={styles.lightboxHint}>{lightbox?.name ?? ''} — tap anywhere to close</Text>
        </TouchableOpacity>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  fpFailTxt: { color: '#e8896b', fontSize: 13, lineHeight: 18, marginBottom: 10 },
  fill: { flex: 1, backgroundColor: '#0b0f14' },
  header: { flexDirection: 'row', alignItems: 'center', padding: 14, borderBottomWidth: 1, borderBottomColor: '#141d25', paddingTop: 44 },
  backBtn: { padding: 6 },
  callBtn: { paddingVertical: 4, paddingHorizontal: 8, marginLeft: 4 },
  callGlyph: { color: '#7cf4c8', fontSize: 20, lineHeight: 24 },
  // b62 groups
  senderLbl: { color: '#5fd4c4', fontSize: 11, marginBottom: 2 },
  groupOverlay: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(3,7,12,0.86)', justifyContent: 'center', padding: 18, zIndex: 40 },
  groupPanel: { backgroundColor: '#0B1018', borderColor: '#1d2a38', borderWidth: 1, borderRadius: 14, padding: 16, maxHeight: '72%' },
  groupPanelHead: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  groupPanelTitle: { color: '#EAF2F6', fontSize: 16, fontWeight: '700' },
  groupCloseTxt: { color: '#7c8a96', fontSize: 18, paddingHorizontal: 6 },
  groupFp: { color: '#8a6d3b', fontSize: 11, marginBottom: 10 },
  groupMemberList: { flexGrow: 0 },
  groupEmpty: { color: '#7c8a96', fontSize: 13, paddingVertical: 8 },
  groupMemberRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 8, borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: '#16202c' },
  groupMemberName: { color: '#EAF2F6', fontSize: 13 },
  groupMemberMeta: { color: '#7c8a96', fontSize: 11, marginTop: 1 },
  evictBtn: { borderColor: '#7c3a3a', borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 5 },
  evictBtnArmed: { backgroundColor: '#7c3a3a' },
  evictBtnTxt: { color: '#f0b8b8', fontSize: 11 },
  rotateBtn: { backgroundColor: '#12323a', borderColor: '#2c5a57', borderWidth: 1, borderRadius: 10, paddingVertical: 10, alignItems: 'center', marginTop: 12 },
  rotateBtnTxt: { color: '#7cf4c8', fontSize: 13, fontWeight: '600' },
  groupErr: { color: '#f0b8b8', fontSize: 12, marginTop: 8 },
  backTxt: { color: '#7cf4c8', fontSize: 14 },
  headerMid: { flex: 1, marginHorizontal: 8 },
  title: { color: '#d7e2e8', fontSize: 15, fontWeight: '600' },
  subtitle: { color: '#41505b', fontSize: 11, marginTop: 2 },
  vBadge: { alignSelf: 'flex-start', marginTop: 6, borderWidth: 1, borderRadius: 999, paddingHorizontal: 8, paddingVertical: 2 },
  vBadgeOk: { borderColor: '#2e6b4f', backgroundColor: 'rgba(63,185,127,0.10)' },
  vBadgeHalf: { borderColor: '#6b5a2e', backgroundColor: 'rgba(245,194,107,0.10)' },
  vBadgeNone: { borderColor: '#2a3a48', backgroundColor: 'transparent' },
  vBadgeTxt: { fontSize: 11, fontWeight: '600' },
  vBadgeTxtOk: { color: '#3fb97f' },
  vBadgeTxtHalf: { color: '#f5c26b' },
  vBadgeTxtNone: { color: '#8aa0b2' },
  newThreadBtn: { borderWidth: 1, borderColor: '#27435a', borderRadius: 8, paddingHorizontal: 10, height: 34, minWidth: 56, alignItems: 'center', justifyContent: 'center' },
  newThreadTxt: { color: '#7fd4ff', fontSize: 13, fontWeight: '600' },
  menuBtn: { paddingHorizontal: 10, paddingVertical: 6 },
  menuTxt: { color: '#7a8b96', fontSize: 22, fontWeight: '700' },
  // (b66) ✕ sheet
  sheetBackdrop: { flex: 1, backgroundColor: 'rgba(3,7,11,0.8)', justifyContent: 'flex-end' },
  sheetPanel: { backgroundColor: '#101920', borderTopLeftRadius: 18, borderTopRightRadius: 18, borderWidth: 1, borderColor: '#22323d', paddingHorizontal: 14, paddingBottom: 34, paddingTop: 6 },
  sheetRow: { paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: '#1a2530' },
  sheetRowTxt: { color: '#d5e3dd', fontSize: 15, fontWeight: '700', textAlign: 'center' },
  sheetRowSub: { color: '#5a6b76', fontSize: 12, marginTop: 3, textAlign: 'center' },
  sheetRowDanger: { paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: '#1a2530' },
  sheetRowDangerTxt: { color: '#ff5a4e', fontSize: 15, fontWeight: '800', textAlign: 'center' },
  sheetRowDangerSub: { color: '#8a5450', fontSize: 12, marginTop: 3, textAlign: 'center' },
  sheetRowCancel: { paddingVertical: 16 },
  // b123: teal read-receipt tick appended to my read bubbles' timestamps
  readTick: { color: '#7cf4c8', fontWeight: '700' },
  // b123: rename-thread modal (VEIL palette: #101920 card, #7cf4c8 accent)
  rnBackdrop: { flex: 1, backgroundColor: 'rgba(3,7,11,0.8)', justifyContent: 'center', alignItems: 'center', padding: 28 },
  rnCard: { width: '100%', backgroundColor: '#101920', borderRadius: 16, borderWidth: 1, borderColor: '#22323d', padding: 18 },
  rnTitle: { color: '#e6f1ed', fontSize: 17, fontWeight: '800', textAlign: 'center' },
  rnBody: { color: '#5a6b76', fontSize: 12, textAlign: 'center', marginTop: 6, marginBottom: 14 },
  rnInput: { backgroundColor: '#0c141c', borderWidth: 1, borderColor: '#1f4a42', borderRadius: 10, color: '#d5e3dd', paddingHorizontal: 12, paddingVertical: 10, fontSize: 15 },
  rnActions: { flexDirection: 'row', marginTop: 14 },
  rnBtnGhost: { flex: 1, alignItems: 'center', paddingVertical: 12, borderRadius: 10, borderWidth: 1, borderColor: '#22323d', marginRight: 8 },
  rnBtnGhostTxt: { color: '#8fa5b0', fontSize: 14, fontWeight: '700' },
  rnBtnTeal: { flex: 1, alignItems: 'center', paddingVertical: 12, borderRadius: 10, backgroundColor: '#7cf4c8' },
  rnBtnTealTxt: { color: '#0c141c', fontSize: 14, fontWeight: '800' },
  sheetCancelTxt: { color: '#7a8b96', fontSize: 15, fontWeight: '700', textAlign: 'center' },
  endBtn: { padding: 6 },
  endTxt: { color: '#8a4b55', fontSize: 13 },
  error: { color: '#d98b8b', fontSize: 12, paddingHorizontal: 16, paddingTop: 8 },
  notice: { color: '#e0a458', fontSize: 12, paddingHorizontal: 16, paddingTop: 4 },
  list: { flex: 1, paddingHorizontal: 12 },
  bubbleRow: { flexDirection: 'row', marginVertical: 3 },
  mineRow: { justifyContent: 'flex-end' },
  peerRow: { justifyContent: 'flex-start' },
  bubble: { maxWidth: '78%', borderRadius: 16, paddingHorizontal: 12, paddingVertical: 8 },
  mediaBubble: { padding: 6 },
  mineBubble: { backgroundColor: '#12514a' },
  peerBubble: { backgroundColor: '#131c24' },
  mineText: { color: '#eafff7', fontSize: 14 },
  peerText: { color: '#d7e2e8', fontSize: 14 },
  mineTs: { color: '#6fa79e', fontSize: 9, marginTop: 3, textAlign: 'right' },
  peerTs: { color: '#3a4750', fontSize: 9, marginTop: 3 },
  mediaImg: { width: 220, height: 220, borderRadius: 12, backgroundColor: '#0e151c' },
  mediaStub: { width: 220, height: 120, borderRadius: 12, backgroundColor: '#0e151c', alignItems: 'center', justifyContent: 'center' },
  mediaStubTxt: { color: '#5a6b76', fontSize: 12, marginTop: 8 },
  mediaErrTxt: { color: '#d98b8b', fontSize: 12 },
  mediaCaption: { color: '#7d919e', fontSize: 10, marginTop: 4, maxWidth: 220 },
  micBtnRec: { backgroundColor: 'rgba(214,160,84,0.15)', borderWidth: 1, borderColor: '#8a6d3b', borderRadius: 8, paddingHorizontal: 10, paddingVertical: 9, marginLeft: 4 },
  micBtnTxt: { color: '#d6a054', fontSize: 12, fontWeight: '600' },
  audioRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 2 },
  audioBtn: { width: 34, height: 34, borderRadius: 17, backgroundColor: 'rgba(127,244,200,0.12)', borderWidth: 1, borderColor: '#2e6b4f', alignItems: 'center', justifyContent: 'center' },
  audioBtnTxt: { color: '#7cf4c8', fontSize: 14 },
  audioLbl: { color: '#aebfc9', fontSize: 12, marginLeft: 8 },
  videoBox: { width: 220, height: 120, borderRadius: 8, backgroundColor: '#101820', borderWidth: 1, borderColor: '#1d2b36', alignItems: 'center', justifyContent: 'center' },
  videoIcon: { color: '#7cf4c8', fontSize: 22 },
  videoLbl: { color: '#7d919e', fontSize: 10, marginTop: 4 },
  pickAudioPreview: { alignItems: 'center', paddingVertical: 14 },
  pickAudioIcon: { fontSize: 34 },
  pickAudioMeta: { color: '#aebfc9', fontSize: 12, marginTop: 6 },
  empty: { padding: 40, alignItems: 'center' },
  captureNotice: {
    color: '#d6a054', textAlign: 'center', fontSize: 11, lineHeight: 15,
    paddingHorizontal: 24, paddingVertical: 6, marginVertical: 4,
  },
  emptyTxt: { color: '#41505b', fontSize: 13, textAlign: 'center', lineHeight: 20 },
  vCard: { marginHorizontal: 12, marginTop: 8, borderRadius: 12, borderWidth: 1, borderColor: '#2a5147', backgroundColor: '#0f1a17' },
  vCardBody: { padding: 14 },
  vCardTitle: { color: '#7cf4c8', fontSize: 13, fontWeight: '700', marginBottom: 4 },
  vCardTxt: { color: '#9db0ba', fontSize: 12, lineHeight: 17 },
  vCardRow: { flexDirection: 'row', alignItems: 'center', marginTop: 10 },
  vCardBtn: { borderRadius: 8, backgroundColor: '#7cf4c8', paddingHorizontal: 12, paddingVertical: 8 },
  vCardBtnTxt: { color: '#06231c', fontSize: 12, fontWeight: '700' },
  vCardSkip: { marginLeft: 10, padding: 6 },
  vCardSkipTxt: { color: '#5a6c76', fontSize: 12 },
  // b126 verification panel
  fpBox: { backgroundColor: '#0c141c', borderWidth: 1, borderColor: '#1f4a42', borderRadius: 10, paddingHorizontal: 12, paddingVertical: 12, color: '#7cf4c8', fontSize: 13, lineHeight: 19, marginTop: 12 },
  fpStepBtn: { alignItems: 'center', paddingVertical: 11, borderRadius: 10, borderWidth: 1, borderColor: '#22323d', marginTop: 12 },
  fpStepBtnOn: { borderColor: '#7cf4c8', backgroundColor: 'rgba(124,244,200,0.08)' },
  fpStepBtnTxt: { color: '#8fa5b0', fontSize: 13, fontWeight: '700' },
  fpStepBtnTxtOn: { color: '#7cf4c8' },
  fpBtnDisabled: { opacity: 0.35 },
  fpStatus: { color: '#9db0ba', fontSize: 12, textAlign: 'center', marginTop: 12, lineHeight: 17 },
  fpPinned: { color: '#7cf4c8', fontSize: 13, fontWeight: '700', textAlign: 'center', marginTop: 12 },
  composer: { flexDirection: 'row', flexWrap: 'wrap', alignItems: 'flex-end', padding: 12, borderTopWidth: 1, borderTopColor: '#141d25' },
  input: { flex: 1, minWidth: 120, minHeight: 42, maxHeight: 110, borderRadius: 20, borderWidth: 1, borderColor: '#1c2a34', color: '#d7e2e8', paddingHorizontal: 14, paddingVertical: 10, fontSize: 14, backgroundColor: '#0e151c' },
  inputLocked: { opacity: 0.5 },
  // b163: composer-level ceremony-gate notice (web P1.2 parity)
  verifyNotice: { flexBasis: '100%', width: '100%', flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 8, paddingLeft: 12, paddingRight: 4 },
  verifyNoticeTxt: { flex: 1, color: '#e8a34a', fontSize: 12, lineHeight: 16 },
  verifyNowBtn: { borderColor: '#7cf4c8', borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 6 },
  verifyNowBtnTxt: { color: '#7cf4c8', fontSize: 12, fontWeight: '700' },
  attachBtn: { marginLeft: 8, height: 42, width: 42, borderRadius: 21, alignItems: 'center', justifyContent: 'center' },
  attachBtnOn: { backgroundColor: '#12202a' },
  attachBtnOff: { backgroundColor: '#0e151c', opacity: 0.5 },
  attachTxt: { fontSize: 20, color: '#7cf4c8' },
  attachTxtOff: { color: '#3a4750' },
  sendBtn: { marginLeft: 8, borderRadius: 20, paddingHorizontal: 18, paddingVertical: 12 },
  sendBtnOn: { backgroundColor: '#7cf4c8' },
  sendBtnOff: { backgroundColor: '#12202a' },
  sendTxt: { fontSize: 13, fontWeight: '700', color: '#2c3942' },
  sendTxtOn: { color: '#06231c' },
  pickOverlay: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.75)', alignItems: 'center', justifyContent: 'center', padding: 16, zIndex: 50, elevation: 50 },
  pickSheet: { width: '100%', maxWidth: 340, borderRadius: 20, backgroundColor: '#101922', borderWidth: 1, borderColor: '#1c2a34', padding: 18, alignItems: 'center' },
  pickTitle: { color: '#d7e2e8', fontSize: 15, fontWeight: '700', marginBottom: 12 },
  pickPreview: { width: '100%', height: 240, borderRadius: 12, backgroundColor: '#0e151c' },
  pickMeta: { color: '#7d919e', fontSize: 11, marginTop: 8 },
  pickBtns: { flexDirection: 'row', marginTop: 16 },
  dlToggle: { flexDirection: 'row', alignItems: 'center', marginTop: 14, alignSelf: 'flex-start' },
  dlBox: { width: 18, height: 18, borderRadius: 5, borderWidth: 1.5, borderColor: '#2c3f4b', marginRight: 8, alignItems: 'center', justifyContent: 'center' },
  dlBoxOn: { backgroundColor: '#123c31', borderColor: '#5fd4c4' },
  dlBoxTxt: { color: '#5fd4c4', fontSize: 12, fontWeight: '700' },
  dlToggleTxt: { color: '#8fa2ad', fontSize: 12 },
  saveBtn: { marginTop: 6, alignSelf: 'flex-end', paddingVertical: 4, paddingHorizontal: 10, borderRadius: 8, backgroundColor: '#122430', borderWidth: 1, borderColor: '#1f3947' },
  saveBtnTxt: { color: '#5fd4c4', fontSize: 11 },
  pickCancel: { flex: 1, borderRadius: 14, backgroundColor: '#12202a', paddingVertical: 12, alignItems: 'center', marginRight: 8 },
  pickCancelTxt: { color: '#9fb3c0', fontSize: 14, fontWeight: '600' },
  pickSend: { flex: 1, borderRadius: 14, backgroundColor: '#7cf4c8', paddingVertical: 12, alignItems: 'center' },
  pickSendTxt: { color: '#06231c', fontSize: 14, fontWeight: '700' },
  lightbox: { flex: 1, backgroundColor: 'rgba(0,0,0,0.94)', alignItems: 'center', justifyContent: 'center', padding: 16 },
  lightboxImg: { width: '100%', height: '82%' },
  lightboxHint: { color: '#7d919e', fontSize: 11, marginTop: 14 },
  // b140: soft large-file warning in the pick preview (send still allowed)
  pickWarn: { color: '#e8a33d', fontSize: 11, marginTop: 6, marginHorizontal: 18, textAlign: 'center' },
  // b140: full-screen video player
  videoFSBg: { flex: 1, backgroundColor: '#000000' },
  videoFSPlayer: { flex: 1 },
  videoFSClose: { position: 'absolute', top: 54, right: 20, width: 40, height: 40, borderRadius: 20, backgroundColor: 'rgba(0,0,0,0.55)', alignItems: 'center', justifyContent: 'center' },
  videoFSCloseTxt: { color: '#ffffff', fontSize: 20, lineHeight: 22 },
  videoFSHint: { color: '#7d919e', fontSize: 11, textAlign: 'center', paddingVertical: 10 },

  // b187: lounge read-only notice
  loungeNoteTxt: {
    flexBasis: '100%',
    width: '100%',
    color: '#7cf4c8',
    fontSize: 12,
    textAlign: 'center',
    paddingBottom: 6,
  },
});
