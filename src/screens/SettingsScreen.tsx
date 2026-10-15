/**
 * Native Settings — NATIVE-PARITY-HANDOFF §2 exact structure:
 * Device protection / Messages / Private storage / Emergency access /
 * Security details / Support / Device transfer / Identity / Appearance /
 * Own VEIL / Account / About / Delete account. (Founder operations — Mission
 * Control — is admin-only and intentionally absent: for everyone else this
 * route is indistinguishable from a page that does not exist.)
 * One mode. Nothing pre-set — every control explained and yours to set.
 */
import React, { useState } from 'react';
import Constants from 'expo-constants';
import { View, Text, TextInput, TouchableOpacity, ScrollView, StyleSheet, Alert, Linking, Share, ActivityIndicator, Image } from 'react-native';
import { useThemedPrompt } from './ThemedPrompt';
import { useThemedShare } from './ThemedSheets';
import {
  type VeilSettings, BURN_OPTIONS, EXPIRY_OPTIONS, QUIET_OPTIONS,
  SELF_DESTRUCT_HOURS, SELF_DESTRUCT_WARN_HOURS,
} from '../../vendor/device/src/settings';

export interface SettingsScreenProps {
  settings: VeilSettings;
  onChange: (s: VeilSettings) => void;
  veilId: string | null;
  email?: string | null;
  /** open the privacy checkup wizard (web parity: /checkup from Settings) */
  onRunCheckup: () => void;
  /** app lock (passcode + Decoy + Duress) configured on this device */
  appLockEnabled: boolean;
  onSetAppLock: (pass: string, decoy?: string | null, duress?: string | null) => Promise<void>;
  onRemoveAppLock: (pass: string) => Promise<boolean>;
  /** Account category */
  onSignOut: () => void;
  onLockNow: () => void;
  onWipeDevice: () => Promise<void>;
  onDeleteAccount: () => Promise<void>;
  onViewIntro: () => void;
  onOpenTools: () => void;
  /** b141: re-open the Getting Started screen (carry-over after "Don't show
   * again") so the Founding Tester Lounge join is always reachable. */
  onOpenWelcome: () => void;
  /** Settings > Identity "Pinned contacts" cross-link (jumps to the Contacts tab) */
  onOpenContacts?: () => void;
  /** web app base for purchase + legal links */
  webBaseUrl: string;
  /** device transfer (web parity): build + upload the encrypted bundle */
  onCreateTransfer: () => Promise<{ link: string; sessionCount: number; groupCount: number; hasIdentity: boolean }>;
  /** device transfer: import sessions/identity from a pasted link */
  onReceiveTransfer: (link: string) => Promise<{ sessionCount: number; importedCount: number; skippedExisting: number; identityImported: boolean; identityKept: boolean }>;
  /** Identity (web parity): local-only 24-word phrase check against the current Veil ID */
  onVerifyPhrase: (phrase: string) => Promise<boolean>;
  /** Identity (web parity "Remove from this device"): drop this device's keyvault copy only */
  onRemoveIdentity: () => Promise<void>;
  /** "Generate new Veil ID" (landing headline feature): remove current identity then run the create flow */
  onGenerateNewVeilId: () => Promise<void>;
  /** open the identity create/restore flow (shown when this device has no identity) */
  onCreateIdentity: () => void;
}

// Real facts about THIS build, shown in Settings > About — never copied from
// the web app's own About card (which tracks a separate governance process:
// Security patch / Claims Register). PROTOCOL_VERSION must match VeilRelay's
// wire contract. b103: BUILD_NUMBER now derives from the NATIVE build number
// embedded in the binary (expo-constants) — a hardcoded constant here drifted
// from b99 through b103 and made the owner believe a fresh build was stale.
const APP_VERSION = '1.0.92';
const BUILD_NUMBER = Constants.expoConfig?.ios?.buildNumber ?? Constants.nativeBuildVersion ?? '?';
const BUILD_DATE = '2026-10-12';
// b122: the native build number is frozen into the EAS binary and never
// changes across staged Metro patches — the owner cannot tell which staged
// source the device is actually running (b109-09-24 read identically for
// b118..b121). SOURCE_TAG is bumped with every staged zip so Settings > About
// always identifies the live JS tree.
const SOURCE_TAG = 'b196-r8';
// b185+: the engine is a SPEC-CONFORMANT Signal Double Ratchet with the single
// custom extension retained — per-step ML-KEM-768 post-quantum re-keying
// (PQ-hybrid). 'veil-ratchet-4' is retired; this string is user-facing and
// must match the audited protocol story, not the legacy engine.
// b188: keep the WIRE TAG first (new sessions still stamp veil-ratchet-4 —
// it is the fail-closed version marker separating the DR engine from legacy
// ratchet-3 sessions) and append the audited engine description.
const PROTOCOL_VERSION = 'Signal DR + ML-KEM-768';
const PROTOCOL_WIRE_TAG = 'wire tag: veil-ratchet-4 · PQ-hybrid';

interface Chip { label: string; value: number }

const BURN_CHIPS: Chip[] = BURN_OPTIONS;
const EXPIRE_CHIPS: Chip[] = EXPIRY_OPTIONS;
const RETENTION_CHIPS: Chip[] = QUIET_OPTIONS;

function ChipRow({ chips, value, onPick }: { chips: Chip[]; value: number; onPick: (v: number) => void }) {
  return (
    <View style={styles.chipRow}>
      {chips.map((c) => (
        <TouchableOpacity
          key={c.label}
          style={[styles.chip, value === c.value && styles.chipOn]}
          onPress={() => onPick(c.value)}
        >
          <Text style={[styles.chipTxt, value === c.value && styles.chipTxtOn]}>{c.label}</Text>
        </TouchableOpacity>
      ))}
    </View>
  );
}

function Toggle({ on, onFlip, label, hint, danger }: { on: boolean; onFlip: () => void; label: string; hint: string; danger?: boolean }) {
  return (
    <TouchableOpacity style={styles.toggleRow} onPress={onFlip} activeOpacity={0.7}>
      <View style={styles.toggleMid}>
        <Text style={styles.toggleLabel}>{label}</Text>
        <Text style={styles.toggleHint}>{hint}</Text>
      </View>
      <View style={[styles.toggleBox, on && (danger ? styles.toggleBoxDangerOn : styles.toggleBoxOn)]}>
        {on ? <Text style={styles.toggleBoxTxt}>✓</Text> : null}
      </View>
    </TouchableOpacity>
  );
}

export function SettingsScreen({
  settings, onChange, veilId, onRunCheckup, appLockEnabled, onSetAppLock, onRemoveAppLock,
  onSignOut, onLockNow, onWipeDevice, onDeleteAccount, onViewIntro, onOpenWelcome, onOpenContacts, webBaseUrl,
  onCreateTransfer, onReceiveTransfer, onVerifyPhrase, onRemoveIdentity, onGenerateNewVeilId, onCreateIdentity,
}: SettingsScreenProps) {
  const [xferBusy, setXferBusy] = useState(false);
  const [xferLink, setXferLink] = useState<{ link: string; sessionCount: number; hasIdentity: boolean } | null>(null);
  const [recvOpen, setRecvOpen] = useState(false);
  const [recvInput, setRecvInput] = useState('');
  const [recvBusy, setRecvBusy] = useState(false);
  const [recvMsg, setRecvMsg] = useState<string | null>(null);
  const [identityArmed, setIdentityArmed] = useState(false);
  const [phraseBusy, setPhraseBusy] = useState(false);
  // (b57) themed replacement for every system Alert.prompt/confirm — the OS
  // alerts are unthemeable white iPhone boxes (owner request).
  const { node: promptNode, ask } = useThemedPrompt();
  // b105: VEIL-branded Veil ID share card (owner request Sept 22 — was the
  // stock Apple share sheet). Copy is the primary action; the system sheet
  // only opens on explicit "Share…".
  const { node: shareNode, share: openShare } = useThemedShare();
  const shareVeilId = () => { if (veilId) openShare({ value: veilId, kicker: 'People use it to look you up and start verified conversations.' }); };

  /** web parity: "Verify recovery phrase" — local-only check, phrase never leaves the device */
  const doVerifyPhrase = async () => {
    const t = (await ask({
      title: 'Verify recovery phrase',
      message: 'Paste your 24-word recovery phrase. It is checked on this device against your Veil ID — the phrase itself never leaves this device.',
      input: 'text',
      submitLabel: 'Verify',
    })) as string | null;
    const phrase = (t || '').trim().toLowerCase();
    if (!phrase) return;
    setPhraseBusy(true);
    try {
      const ok = await onVerifyPhrase(phrase);
      await ask({
        title: ok ? 'Phrase verified' : 'Not this identity',
        message: ok
          ? 'Phrase verified — it matches the identity key published to the relay.'
          : 'This recovery phrase belongs to a different Veil identity.',
        info: true,
      });
    } catch {
      await ask({ title: 'Not this identity', message: 'This recovery phrase belongs to a different Veil identity.', info: true });
    } finally {
      setPhraseBusy(false);
    }
  };

  /** landing headline: "Generate new Veil ID" — fresh keys, fresh ID, nothing linking old to new */
  const doGenerateNewVeilId = async () => {
    const ok = (await ask({
      title: 'Generate new Veil ID',
      message: 'Creates a fresh identity — new keys and a new Veil ID, with nothing linking it to the old one. Your current identity is removed from this device first; it stays recoverable only with its 24-word recovery phrase. Contacts, pins and existing conversation keys are kept — new threads will use the new identity.',
      confirm: true,
      danger: true,
    })) as boolean;
    if (!ok) return;
    setIdentityArmed(false);
    try {
      await onGenerateNewVeilId();
    } catch (e) {
      await ask({ title: 'Could not generate a new identity', message: String((e as Error).message || e), info: true });
    }
  };

  /** web parity: "Remove from this device" — two-tap armed, drops the keyvault copy only */
  const doRemoveIdentity = () => {
    if (identityArmed) {
      setIdentityArmed(false);
      onRemoveIdentity().catch((e) =>
        ask({ title: 'Could not remove the identity', message: String((e as Error).message || e), info: true }));
    } else {
      setIdentityArmed(true);
    }
  };

  const doCreateTransfer = async () => {
    setXferBusy(true); setXferLink(null);
    try {
      const r = await onCreateTransfer();
      setXferLink({ link: r.link, sessionCount: r.sessionCount, hasIdentity: r.hasIdentity });
    } catch (e) {
      void ask({ title: 'Transfer link could not be created', message: String((e as Error).message || e), info: true });
    } finally { setXferBusy(false); }
  };

  const doReceiveTransfer = async () => {
    setRecvBusy(true); setRecvMsg(null);
    try {
      const r = await onReceiveTransfer(recvInput.trim());
      setRecvMsg(
        `Imported ${r.importedCount} conversation${r.importedCount === 1 ? '' : 's'}`
        + (r.skippedExisting ? ` (${r.skippedExisting} already on this device — not overwritten)` : '')
        + (r.identityImported ? ' and your identity.' : r.identityKept ? '. This device\u2019s existing identity was kept.' : '.'),
      );
      setRecvInput('');
    } catch (e) {
      void ask({ title: 'Transfer failed', message: String((e as Error).message || e), info: true });
    } finally { setRecvBusy(false); }
  };
  const set = (patch: Partial<VeilSettings>) => onChange({ ...settings, ...patch });

  /**
   * b105 two-tap key storage change (owner request Sept 22): tap 1 shows what
   * the switch will actually do; tap 2 (Confirm) executes it. The hardware
   * flip's own Face ID demand then fires as part of the switch, as in b104.
   */
  const confirmKeyMode = async (mode: 'device' | 'hardware' | 'memory') => {
    if (settings.storageMode === mode) return;
    const warnings: Record<'device' | 'hardware' | 'memory', string> = {
      device: 'Your identity keys will move into encrypted on-device storage. They persist across restarts and nothing is demanded at boot. Weaker against a seized device — the stored keys exist in a full device image. Conversations keep working unchanged.',
      hardware: 'Your identity keys will be re-sealed inside the Secure Enclave. The phone itself will demand Face ID at boot and at this switch — if biometry is off, broken or re-enrolled, the keys become unreachable and the app falls back to restoring from your 24-word phrase. Strongest protection against extraction from a seized device.',
      memory: 'The moment VEIL leaves the foreground or the screen locks, ALL local data is wiped: chats, notes, vaults, saved stego images and your identity keys. Local history is forced off. Wiped chat threads can NEVER be reopened. Your 24-word phrase restores identity and notes; vaults reopen with their passphrases. Account login, contacts and settings survive.',
    };
    const labels: Record<'device' | 'hardware' | 'memory', string> = {
      device: 'Switch to Sealed-at-rest',
      hardware: 'Switch to security chip',
      memory: 'Switch to Nothing-at-Rest',
    };
    const ok = await ask({ title: 'Change key storage?', message: warnings[mode], confirm: true, submitLabel: labels[mode] });
    if (ok !== true) return;
    if (mode === 'memory') set({ storageMode: mode, localHistory: false });
    else set({ storageMode: mode });
  };
  const [wipeArmed, setWipeArmed] = useState(0);

  const armWipe = () => {
    const id = Date.now();
    setWipeArmed(id);
    setTimeout(() => setWipeArmed((a) => (a === id ? 0 : a)), 6000);
  };

  const setLockCodes = async () => {
    const pass = (await ask({
      title: 'Set your passcode',
      message: 'At least 4 digits. Use it to unlock VEIL.',
      input: 'secure',
      numeric: true,
      submitLabel: 'Next',
    })) as string | null;
    if (!pass) return;
    if (pass.length < 4) { await ask({ title: 'Passcode too short', message: 'Use at least 4 digits.', info: true }); return; }
    const decoy = (await ask({
      title: 'Decoy code (optional)',
      message: 'Cancel to skip. Opens a harmless empty environment if entered at the lock screen.',
      input: 'secure',
      numeric: true,
      submitLabel: 'Next',
    })) as string | null;
    const duress = (await ask({
      title: 'Duress code (optional)',
      message: 'Cancel to skip. Best-effort deletion of VEIL data if entered at the lock screen.',
      input: 'secure',
      numeric: true,
      submitLabel: 'Save',
    })) as string | null;
    try {
      await onSetAppLock(pass, decoy || null, duress || null);
    } catch (e) {
      await ask({ title: 'Could not save', message: String((e as Error).message || e), info: true });
    }
  };

  // self-destruct countdown state
  const sdArmedAt = settings.selfDestructArmedAt || 0;
  const sdElapsedH = sdArmedAt ? (Date.now() - sdArmedAt) / 3600000 : 0;
  const sdWarn = settings.selfDestruct && sdElapsedH >= SELF_DESTRUCT_WARN_HOURS;

  const selfDestructRow = settings.selfDestruct ? (
    <View style={styles.sdBox}>
      <Text style={styles.sdTxt}>
        {sdWarn
          ? `Self-destruct in under ${Math.max(1, Math.ceil(SELF_DESTRUCT_HOURS - sdElapsedH))} hour(s). Wiping removes everything VEIL keeps on this device — extend if you are still using it.`
          : `Self-destruct armed — everything wipes in ${Math.max(1, Math.ceil(SELF_DESTRUCT_HOURS - sdElapsedH))} hour(s). Messaging does not reset the clock.`}
      </Text>
      <TouchableOpacity style={styles.sdExtendBtn} onPress={() => set({ selfDestructArmedAt: Date.now() })}>
        <Text style={styles.sdExtendTxt}>Extend by another 48 hours</Text>
      </TouchableOpacity>
    </View>
  ) : null;

  return (
    <View style={styles.fill}>
    <ScrollView style={styles.fill} contentContainerStyle={styles.content}>
      <Text style={styles.headline}>Settings</Text>
      <Text style={styles.tag}>One mode. Nothing pre-set — every control explained and yours to set.</Text>

      {/* ---- 1. Device protection ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Device protection</Text>
        <Text style={styles.sectionHint}>New conversations take their lifetime and auto-end window from these controls.</Text>

        <View style={styles.dial}>
          <Text style={styles.dialName}>Burn after opening</Text>
          <Text style={styles.dialDesc}>Messages delete themselves this long after the recipient reads them. Off = threads never burn after opening.</Text>
          <Text style={styles.defends}>Defends against: someone later opening the device and re-reading conversations.</Text>
          <ChipRow chips={BURN_CHIPS} value={settings.burnTtlSeconds} onPick={(v) => set({ burnTtlSeconds: v })} />
        </View>

        <View style={styles.dial}>
          <Text style={styles.dialName}>Unopened messages: relay deletion</Text>
          <Text style={styles.dialDesc}>If a message is never opened, the relay deletes it this long after sending. Independent of the burn dial: opened messages burn on the burn-after-open clock; unopened ones die on this clock.</Text>
          <Text style={styles.defends}>Defends against: unopened messages accumulating on the relay.</Text>
          {/* b198: the 30-day tier — the Founding Tester Forum's backlog lifetime */}
          <ChipRow chips={[{ label: '12 h', value: 43200 }, { label: '24 h', value: 86400 }, { label: '36 h', value: 129600 }, { label: '48 h', value: 172800 }, { label: '30 d', value: 2592000 }]} value={settings.expireAfterSeconds} onPick={(v) => set({ expireAfterSeconds: v })} />
        </View>

        <View style={styles.dial}>
          <Text style={styles.dialName}>End quiet threads after</Text>
          <Text style={styles.dialDesc}>A conversation with no messages for this long ends and deletes itself on the relay. Off = never ended automatically.</Text>
          <Text style={styles.defends}>Defends against: old conversations lingering on the relay.</Text>
          <ChipRow chips={RETENTION_CHIPS} value={settings.retentionHours} onPick={(v) => set({ retentionHours: v })} />
        </View>

        <Text style={styles.fixedNote}>Auto-lock: VEIL locks itself after 1 minute of inactivity, always on.</Text>

        <View style={styles.dial}>
          <Text style={styles.dialName}>App lock</Text>
          <Text style={styles.dialDesc}>
            {appLockEnabled
              ? 'On — a passcode is required every time VEIL is opened. Decoy and Duress codes may also be set (Emergency access below).'
              : 'Off — VEIL opens straight into your conversations. Set a passcode to lock this app on this device.'}
          </Text>
          <TouchableOpacity style={styles.checkupBtn} onPress={setLockCodes}>
            <Text style={styles.checkupBtnTxt}>{appLockEnabled ? 'Change passcode · Decoy · Duress' : 'Set up app lock'}</Text>
          </TouchableOpacity>
        </View>

        <Toggle
          on={settings.localHistory}
          onFlip={() => set({ localHistory: !settings.localHistory })}
          label="Read messages in the moment (no stored history) — ON keeps history"
          hint={settings.storageMode === 'memory'
            ? 'Forced off while Nothing-at-Rest is on.'
            : 'When ON: an encrypted local copy of chats so they survive a reload. When OFF: read-in-the-moment mode — messages appear only while the thread is open, then vanish permanently, INCLUDING messages you sent. The relay cannot restore them: leave without reading and they are gone from this device. Nothing is written to disk.'}
        />

        {/* b105 (owner request, Sept 22): Key storage lives in its own box
            with orange descriptions, and changing modes is two-tap — the
            first tap shows what the change does, the second executes. */}
        <View style={[styles.section, { marginTop: 14 }]}>
          <Text style={styles.sectionTitle}>Key storage</Text>
          <View style={styles.chipRow}>
            <TouchableOpacity style={[styles.chip, settings.storageMode === 'device' && styles.chipOn]} onPress={() => { void confirmKeyMode('device'); }}>
              <Text style={[styles.chipTxt, settings.storageMode === 'device' && styles.chipTxtOn]}>Sealed-at-rest</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.chip, settings.storageMode === 'hardware' && styles.chipOn]}
              onPress={() => { void confirmKeyMode('hardware'); }}
            >
              <Text style={[styles.chipTxt, settings.storageMode === 'hardware' && styles.chipTxtOn]}>Locked in your phone’s security chip</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.chip, settings.storageMode === 'memory' && styles.chipOn]}
              onPress={() => { void confirmKeyMode('memory'); }}
            >
              <Text style={[styles.chipTxt, settings.storageMode === 'memory' && styles.chipTxtOn]}>Nothing-at-Rest</Text>
            </TouchableOpacity>
          </View>
          <Text style={styles.keyModeDesc}>
            {settings.storageMode === 'hardware'
              ? 'Your identity keys are sealed inside your phone’s Secure Enclave — a hardware key that never leaves the chip. Face ID, Touch ID or passcode is demanded by the phone itself before they can be unlocked, and the stored copy is useless off this device.'
              : settings.storageMode === 'memory'
                ? 'Nothing Veil-stored is ever kept on this device. The moment VEIL leaves the foreground — including locking your screen — chats, notes, vaults, saved stego images and your identity are wiped. Your 24-word recovery phrase restores your identity and your notes; vaults reopen with their passphrase. Wiped chat threads can never be reopened. Your account login, contacts and these settings survive.'
                : 'Conversation keys and identity are stored encrypted on this device. They persist across app restarts so conversations keep working.'}
          </Text>
          <Text style={styles.keyDefends}>Defends against: keys being extracted from a seized device. Nothing-at-Rest forces local history off.</Text>
        </View>

        <Toggle
          on={settings.holdUntilUnlock}
          onFlip={() => set({ holdUntilUnlock: !settings.holdUntilUnlock })}
          label="Hold until unlock"
          hint="Delivery is held while the phone is locked — a locked phone holds no message data at all."
        />

        <Text style={styles.sectionHint}>Screen capture protection is ALWAYS ON — there is no setting and no opt-out. Screen recordings are blocked outright while VEIL is open, the app-switcher preview is always blurred, and if a plain screenshot is taken (which no app on iOS — VEIL included — can block or redact), both of you are told immediately over the encrypted channel. The protection exists for the person being captured, so it is not in the captured person's hands.</Text>

        <Toggle
          on={settings.selfDestruct}
          onFlip={() => set({ selfDestruct: !settings.selfDestruct, selfDestructArmedAt: !settings.selfDestruct ? Date.now() : 0 })}
          label="Self-destruct countdown"
          hint={`Everything VEIL keeps on the device wipes on a fixed ${SELF_DESTRUCT_HOURS}-hour clock; messaging does not reset it, a warning appears 12 hours before, extendable by another ${SELF_DESTRUCT_HOURS} h. Opt-in — never armed silently.`}
          danger
        />
        {selfDestructRow}

        <TouchableOpacity style={styles.checkupBtn} onPress={onRunCheckup}>
          <Text style={styles.checkupBtnTxt}>Run the privacy checkup</Text>
        </TouchableOpacity>
      </View>

      {/* ---- 2. Messages ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Messages</Text>
        <Text style={styles.sectionHint}>New conversations take their lifetime and auto-end window from your privacy controls; confirming who you're speaking with is always required before messages can be sent.</Text>
        <Toggle
          on={settings.readReceipts}
          onFlip={() => set({ readReceipts: !settings.readReceipts })}
          label="Read receipts"
          hint="When ON, the sender sees a read mark. When OFF, read marks stop — but a delivery acknowledgement is still sent, so the sender knows your app received the message (and this keeps the receipt ledger consistent: re-enabling later won't retroactively mark old messages as read)."
        />
        <Text style={styles.sectionHint}>Notifications: VEIL shows a single constant, contentless alert ("VEIL / Notification") — never message content, senders, or badges.</Text>
      </View>

      {/* ---- 3. Private storage ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Private storage</Text>
        <Text style={styles.sectionHint}>Vaults, private Notes and image steganography each have their own tab along the bottom — Chat · Contacts · Vault · Stego · Notes · Settings. Everything is encrypted on this device before anything leaves it — the server only ever sees ciphertext or random bytes.</Text>
      </View>

      {/* ---- 4. Device transfer ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Device transfer</Text>
        <Text style={styles.sectionHint}>Move your conversations and identity to another device with a single-use link. The bundle is encrypted on this device and travels through private storage — the key lives only in the link itself. Works once, expires in about 10 minutes. Never send it to anyone else.</Text>
        <TouchableOpacity style={styles.checkupBtn} onPress={doCreateTransfer} disabled={xferBusy}>
          {xferBusy ? <ActivityIndicator color="#7cf4c8" size="small" /> : <Text style={styles.checkupBtnTxt}>Transfer to a new device</Text>}
        </TouchableOpacity>
        {xferLink ? (
          <View style={styles.xferBox}>
            <Text style={styles.xferCount}>
              Link ready — {xferLink.sessionCount} conversation{xferLink.sessionCount === 1 ? '' : 's'}
              {xferLink.hasIdentity ? ' + identity' : ''}. Share it with your other device now.
            </Text>
            <TouchableOpacity style={styles.checkupBtn} onPress={() => Share.share({ message: xferLink.link }).catch(() => {})}>
              <Text style={styles.checkupBtnTxt}>Share / copy the link</Text>
            </TouchableOpacity>
            <TouchableOpacity onPress={() => setXferLink(null)}>
              <Text style={styles.linkTxt}>Dismiss</Text>
            </TouchableOpacity>
          </View>
        ) : null}
        <TouchableOpacity style={styles.linkRow} onPress={() => setRecvOpen(!recvOpen)}>
          <Text style={styles.linkTxt}>Receive a transfer from a link</Text>
        </TouchableOpacity>
        {recvOpen ? (
          <View>
            <TextInput
              style={styles.recvInput}
              autoCapitalize="none"
              autoCorrect={false}
              placeholder="Paste the transfer link…"
              placeholderTextColor="#3b4b56"
              value={recvInput}
              editable={!recvBusy}
              onChangeText={(t) => { setRecvInput(t); setRecvMsg(null); }}
            />
            <TouchableOpacity
              style={[styles.checkupBtn, recvInput.length < 10 && styles.btnXferOff]}
              disabled={recvBusy || recvInput.length < 10}
              onPress={doReceiveTransfer}
            >
              {recvBusy ? <ActivityIndicator color="#7cf4c8" size="small" /> : <Text style={styles.checkupBtnTxt}>Import onto this device</Text>}
            </TouchableOpacity>
            {recvMsg ? <Text style={styles.recvOk}>{recvMsg}</Text> : null}
          </View>
        ) : null}
      </View>

      {/* ---- 5. Emergency access ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Emergency access</Text>
        <Text style={styles.sectionHint}>A Decoy code opens a separate, harmless-looking environment instead of your real one. A Duress code initiates a best-effort deletion of VEIL data and opens an empty environment. Honest limits: server deletion requires network access and cannot be guaranteed if VEIL or its hosting platform is unreachable. Device and operating-system artifacts outside VEIL's control are not deleted. The relay's copies of expired conversations expire on their own schedule.</Text>
        {appLockEnabled ? (
          <TouchableOpacity
            style={[styles.checkupBtn, styles.lockRemoveBtn]}
            onPress={async () => {
              const pass = (await ask({
                title: 'Enter your current passcode',
                message: 'Required to remove the app lock.',
                input: 'secure',
                numeric: true,
                submitLabel: 'Remove',
              })) as string | null;
              if (!pass) return;
              const ok = await onRemoveAppLock(pass);
              if (!ok) await ask({ title: 'Incorrect passcode', message: 'The app lock was not changed.', info: true });
            }}
          >
            <Text style={[styles.checkupBtnTxt, { color: '#e8836f' }]}>Remove app lock</Text>
          </TouchableOpacity>
        ) : null}
      </View>

      {/* ---- 5. Security details ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Security Centre</Text>
        <Text style={styles.sectionHint}>The live security state of this device, explained in four protection layers. Claims are always labelled Implemented / Experimental / Not claimed.</Text>
        <TouchableOpacity style={styles.idRow} onPress={() => Linking.openURL(webBaseUrl)}>
          <View style={{ flex: 1 }}>
            <Text style={styles.idRowTitle}>Open the Security Centre on the web</Text>
            <Text style={styles.idRowSub}>Session details, claims register and account recovery.</Text>
          </View>
          <Text style={styles.idRowArrow}>→</Text>
        </TouchableOpacity>
      </View>

      {/* ---- 7. Support ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Support</Text>
        <TouchableOpacity style={styles.linkRow} onPress={() => Linking.openURL('mailto:support@tryveil.app')}>
          <Text style={styles.linkTxt}>Report a problem — support@tryveil.app</Text>
        </TouchableOpacity>
        <Text style={styles.sectionHint}>Describe the problem (abuse / bug / other). Include your Veil ID only if you want a reply.</Text>
      </View>

      {/* ---- 9. Identity (b67: presented as a proper identity card, web-style) ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Identity</Text>
        {veilId ? (
          <View style={styles.idCard}>
            <View style={styles.idCardHead}>
              <Image source={require('../../assets/logo.png')} style={styles.idCardLogo} />
              <View style={{ flex: 1 }}>
                <Text style={styles.idCardKicker}>Your Veil identity</Text>
                <Text style={styles.idCardId} numberOfLines={1} adjustsFontSizeToFit>{veilId}</Text>
              </View>
              <TouchableOpacity onPress={shareVeilId}>
                <Text style={styles.idCardCopy}>Share</Text>
              </TouchableOpacity>
            </View>
            <Text style={styles.idCardLine}>Keys sealed in this device’s keychain · recoverable only with your 24-word phrase</Text>
            <Text style={styles.idCardLine}>Nickname: {settings.nickname || 'not set'}</Text>
          </View>
        ) : null}
        {veilId ? (
          <View>
            <TouchableOpacity style={styles.idRow} onPress={shareVeilId}>
              <View style={{ flex: 1 }}>
                <Text style={styles.idRowTitle}>Copy / share your Veil ID</Text>
                <Text style={styles.idRowSub}>People use it to look you up and start verified conversations.</Text>
              </View>
              <Text style={styles.idRowArrow}>→</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.idRow} onPress={async () => {
              const t = (await ask({
                title: 'Device nickname',
                message: 'The name the other person sees in conversations you start — stored with your session record, so the server can see it too. Leave it empty to appear as your Veil ID. You can change it any time.',
                input: 'text',
                defaultValue: settings.nickname ?? '',
                submitLabel: 'Save',
              })) as string | null;
              if (t === null) return;
              set({ nickname: t.trim() });
            }}>
              <View style={{ flex: 1 }}>
                <Text style={styles.idRowTitle}>{settings.nickname ? 'Change nickname' : 'Set a nickname'}</Text>
                <Text style={styles.idRowSub}>{settings.nickname ? `People see “${settings.nickname}” in chats you start.` : 'What the other person sees when you start a new chat — instead of your Veil ID.'}</Text>
              </View>
              <Text style={styles.idRowArrow}>→</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.idRow} onPress={doVerifyPhrase} disabled={phraseBusy}>
              <View style={{ flex: 1 }}>
                <Text style={styles.idRowTitle}>{phraseBusy ? 'Verifying…' : 'Verify recovery phrase'}</Text>
                <Text style={styles.idRowSub}>Check your 24-word phrase locally — it never leaves this device.</Text>
              </View>
              <Text style={styles.idRowArrow}>→</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.idRow} onPress={doGenerateNewVeilId}>
              <View style={{ flex: 1 }}>
                <Text style={styles.idRowTitle}>Generate new Veil ID</Text>
                <Text style={styles.idRowSub}>A fresh identity with a new 24-word phrase. Your current identity is replaced.</Text>
              </View>
              <Text style={styles.idRowArrow}>→</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.idRow} onPress={doRemoveIdentity}>
              <View style={{ flex: 1 }}>
                <Text style={[styles.idRowTitle, styles.dangerTxt]}>{identityArmed ? 'Tap again to confirm removal' : 'Remove from this device'}</Text>
                <Text style={styles.idRowSub}>Drops this device’s copy of the identity keys. Without your recovery phrase the identity cannot be restored here.</Text>
              </View>
              <Text style={styles.idRowArrow}>→</Text>
            </TouchableOpacity>
          </View>
        ) : (
          <View>
            <Text style={styles.sectionHint}>Create a keypair identity: Ed25519 identity key, X25519 signed prekey and an ML-KEM-768 prekey, generated on this device. You get a Veil ID and a one-time 24-word recovery phrase. The relay stores public keys only.</Text>
            <TouchableOpacity style={styles.linkRow} onPress={onCreateIdentity}>
              <Text style={styles.linkTxt}>Create anonymous identity</Text>
            </TouchableOpacity>
          </View>
        )}
        <Text style={styles.sectionHint}>Your identity is recoverable with its 24-word phrase. Conversations are not — use Device transfer above to move them between devices. If a contact cannot reach you after you restored a phrase, republish your identity (create a new identity or re-pin on their side), then request again.</Text>
        <Text style={styles.sectionHint}>Names you give pinned contacts stay on this device. Your own nickname (above) is the only name VEIL ever sends anyone — and only inside the sessions you start.</Text>
      </View>

      {/* ---- 11. Own VEIL (pricing notice — flight testing only, no checkout) ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Own VEIL</Text>
        <Text style={styles.sectionHint}>
          After the TestFlight stage, VEIL becomes a one-time payment of A$14.99 — never pay again.
        </Text>
        <Text style={styles.priceSub}>Your account is free while flight testing. No checkout, no subscription, ever.</Text>
      </View>

      {/* ---- 12. Account ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Account</Text>
        <TouchableOpacity style={styles.checkupBtn} onPress={onLockNow}>
          <Text style={styles.checkupBtnTxt}>Lock now</Text>
        </TouchableOpacity>
        <Text style={styles.sectionHint}>Locking hides the app behind your lock screen and keeps the conversation in memory. Messages live for up to {(Math.max(1, Math.round((settings.expireAfterSeconds || 86400) / 3600)) >= 48) ? Math.round((settings.expireAfterSeconds || 86400) / 86400) : Math.max(1, Math.round((settings.expireAfterSeconds || 86400) / 3600))} {(Math.max(1, Math.round((settings.expireAfterSeconds || 86400) / 3600)) >= 48) ? 'days' : 'hours'} after they are sent — the clock comes from your privacy mode.</Text>
        <TouchableOpacity style={styles.linkRow} onPress={onOpenWelcome}>
          <Text style={styles.linkTxt}>Getting started — join the Founding Tester Lounge</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.linkRow} onPress={onViewIntro}>
          <Text style={styles.linkTxt}>View the introduction</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.linkRow} onPress={onSignOut}>
          <Text style={styles.linkTxt}>Sign out</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.linkRow, styles.dangerRow]}
          onPress={() => {
            if (!wipeArmed) { armWipe(); return; }
            setWipeArmed(0);
            onWipeDevice();
          }}
        >
          <Text style={[styles.linkTxt, styles.dangerTxt]}>
            {wipeArmed ? 'Tap again within 6 seconds to wipe — no recovery from this device' : 'Wipe VEIL data from this device'}
          </Text>
        </TouchableOpacity>
      </View>

      {/* ---- 13. About + legal ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>About</Text>
        <View style={styles.infoRow}>
          <Text style={styles.toggleLabel}>Product version</Text>
          <Text style={styles.infoRowValue}>veil-native-{APP_VERSION}</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.toggleLabel}>Build identifier</Text>
          <View style={styles.infoRowValueWrap}><Text style={styles.infoRowValue}>{SOURCE_TAG} · native b{BUILD_NUMBER}</Text><Text style={styles.infoRowSub}>{BUILD_DATE}</Text></View>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.toggleLabel}>Protocol</Text>
          <View style={styles.infoRowValueWrap}>
            <Text style={styles.infoRowValue}>{PROTOCOL_VERSION}</Text>
            <Text style={styles.infoRowSub}>{PROTOCOL_WIRE_TAG}</Text>
          </View>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.toggleLabel}>Environment</Text>
          <Text style={styles.infoRowValue}>Production domain</Text>
        </View>
        <Text style={styles.sectionHint}>The build identifier changes with each App Store / TestFlight submission. If something looks off after an update, confirm this device has installed the latest build from TestFlight or the App Store — a stale local install is the usual cause.</Text>
        <View style={styles.aboutLinksRow}>
          <TouchableOpacity onPress={() => Linking.openURL(webBaseUrl + '/privacy')}>
            <Text style={styles.aboutLinkTxt}>Privacy Policy</Text>
          </TouchableOpacity>
          <Text style={styles.aboutLinkSep}>·</Text>
          <TouchableOpacity onPress={() => Linking.openURL(webBaseUrl + '/terms')}>
            <Text style={styles.aboutLinkTxt}>Terms of Use</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* ---- 14. Delete account ---- */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Delete account</Text>
        <Text style={styles.sectionHint}>Permanently deletes everything this account owns: sessions and their encrypted envelopes, vault records, notes, contacts, device-transfer records, group memberships and published identities — plus the keys on this device. Uploaded encrypted containers stay in private storage as unreferenced ciphertext — they should be inaccessible if encryption and key destruction operate correctly. Whether the hosting platform eventually removes such blobs under storage retention is outside VEIL's control. This cannot be undone.</Text>
        <View style={styles.warnBox}>
          <Text style={styles.warnTxt}>Uploaded encrypted containers may remain as unreferenced ciphertext under the hosting provider's retention policies. They should be inaccessible if encryption and key destruction work correctly.</Text>
        </View>
        <TouchableOpacity
          style={[styles.checkupBtn, styles.lockRemoveBtn]}
          onPress={async () => {
            const t = (await ask({
              title: 'Type DELETE to confirm',
              message: 'Account deletion is permanent. Nothing was deleted until you confirm.',
              input: 'text',
              submitLabel: 'Delete everything',
            })) as string | null;
            if (t === null) return;
            if (t.trim() !== 'DELETE') { await ask({ title: 'Nothing was deleted', message: 'Type DELETE to confirm.', info: true }); return; }
            onDeleteAccount();
          }}
        >
          <Text style={[styles.checkupBtnTxt, { color: '#e8836f' }]}>Delete account</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.footer}>
        <Text style={styles.footerTitle}>VEIL — private conversations and personal information, under your control.</Text>
      </View>
    </ScrollView>
    {promptNode}
{shareNode}
    </View>
  );
}

const styles = StyleSheet.create({
  dial: { marginTop: 14 },
  dialName: { color: '#cfe3dd', fontSize: 13, fontWeight: '700', marginBottom: 3 },
  // Owner request (Sept 19): anything that is merely a DESCRIPTION or
  // explanation (not a tappable setting/label) renders light orange, so
  // info text is visually distinct from white/teal setting labels.
  dialDesc: { color: '#e6eef2', fontSize: 11, lineHeight: 15, marginBottom: 3 },
  keyModeDesc: { color: '#d69a5c', fontSize: 11, lineHeight: 15, marginBottom: 3 },
  keyDefends: { color: '#d69a5c', fontSize: 10, fontStyle: 'italic', marginBottom: 4 },
  defends: { color: '#e6eef2', fontSize: 10, fontStyle: 'italic', marginBottom: 6 },
  fixedNote: { color: '#e6eef2', fontSize: 11, marginTop: 14 },
  sdBox: { borderWidth: 1, borderColor: '#e8836f', borderRadius: 8, padding: 10, marginTop: 8 },
  sdTxt: { color: '#e8836f', fontSize: 11, lineHeight: 15 },
  sdExtendBtn: { marginTop: 8, alignSelf: 'flex-start' },
  sdExtendTxt: { color: '#7cf4c8', fontSize: 12, fontWeight: '700' },
  linkRow: { paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: '#121b22' },
  linkTxt: { color: '#7cf4c8', fontSize: 13 },
  dangerRow: { borderBottomWidth: 0 },
  dangerTxt: { color: '#e8836f' },
  fill: { flex: 1, backgroundColor: '#0b0f14' },
  content: { padding: 20, paddingBottom: 60 },
  headline: { color: '#7cf4c8', fontSize: 22, fontWeight: '700', letterSpacing: 1 },
  tag: { color: '#e6eef2', fontSize: 12, marginTop: 6, marginBottom: 8 },
  lockRemoveBtn: { marginTop: 10, borderColor: '#e8836f' },
  limitsTxt: { color: '#41505b', fontSize: 10, lineHeight: 14, marginTop: 10 },
  checkupBtn: { borderWidth: 1, borderColor: '#7cf4c8', borderRadius: 8, padding: 12, alignItems: 'center' },
  checkupBtnTxt: { color: '#7cf4c8', fontSize: 13, fontWeight: '600' },
  section: { borderWidth: 1, borderColor: '#1f4a42', borderRadius: 12, padding: 14, marginBottom: 12, backgroundColor: '#0c141c' },
  sectionTitle: { color: '#7cf4c8', fontSize: 12, fontWeight: '800', letterSpacing: 0.6, textTransform: 'uppercase', marginBottom: 10 },
  sectionHint: { color: '#e6eef2', fontSize: 12, lineHeight: 17, marginBottom: 12 },
  priceSub: { color: '#9db3ad', fontSize: 12, lineHeight: 17 },
  chipRow: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  chip: { borderWidth: 1, borderColor: '#2a3b46', borderRadius: 8, paddingHorizontal: 12, paddingVertical: 8, marginRight: 8, marginBottom: 8 },
  chipOn: { borderColor: '#7cf4c8', backgroundColor: 'rgba(124,244,200,0.12)' },
  chipTxt: { color: '#5a6b76', fontSize: 12, fontWeight: '600' },
  chipTxtOn: { color: '#7cf4c8' },
  toggleRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 14, borderBottomWidth: 1, borderBottomColor: '#141d25' },
  toggleMid: { flex: 1, paddingRight: 12 },
  toggleLabel: { color: '#cfe3dd', fontSize: 14, fontWeight: '600' },
  toggleHint: { color: '#e6eef2', fontSize: 11, lineHeight: 16, marginTop: 3 },
  toggleBox: { width: 24, height: 24, borderRadius: 6, borderWidth: 1, borderColor: '#2a3b46', alignItems: 'center', justifyContent: 'center' },
  toggleBoxOn: { borderColor: '#7cf4c8', backgroundColor: 'rgba(124,244,200,0.12)' },
  toggleBoxDangerOn: { borderColor: '#e8836f', backgroundColor: 'rgba(232,131,111,0.12)' },
  toggleBoxTxt: { color: '#7cf4c8', fontSize: 13, fontWeight: '700' },
  xferBox: { borderWidth: 1, borderColor: '#1f4a42', borderRadius: 10, padding: 12, marginTop: 10, backgroundColor: 'rgba(124,244,200,0.05)' },
  xferCount: { color: '#cfe3dd', fontSize: 12, lineHeight: 17, marginBottom: 8 },
  recvInput: { color: '#e6eef2', backgroundColor: '#0e151c', borderWidth: 1, borderColor: '#223039', borderRadius: 10, paddingHorizontal: 12, paddingVertical: 10, fontSize: 12, marginBottom: 8 },
  recvOk: { color: '#7cf4c8', fontSize: 12, lineHeight: 17, marginTop: 8 },
  btnXferOff: { opacity: 0.35 },
  infoRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: '#141d25' },
  infoRowValue: { color: '#7a8b96', fontSize: 12, fontFamily: 'monospace', flexShrink: 1, textAlign: 'right' },
  infoRowValueWrap: { flex: 1, alignItems: 'flex-end', marginLeft: 12 },
  infoRowSub: { color: '#566873', fontSize: 10, fontFamily: 'monospace', marginTop: 2, textAlign: 'right' },
  aboutLinksRow: { flexDirection: 'row', justifyContent: 'center', alignItems: 'center', marginTop: 14, gap: 10 },
  aboutLinkTxt: { color: '#7cf4c8', fontSize: 12, textDecorationLine: 'underline' },
  aboutLinkSep: { color: '#3b4b56', fontSize: 12 },
  warnBox: { borderWidth: 1, borderColor: '#c99a4a', borderRadius: 8, padding: 10, marginBottom: 12, backgroundColor: 'rgba(201,154,74,0.08)' },
  warnTxt: { color: '#d9ac5c', fontSize: 11, lineHeight: 16 },
  footer: { marginTop: 28 },
  footerTitle: { color: '#8aa0ad', fontSize: 12, fontWeight: '600', marginBottom: 8 },
  footerLine: { color: '#41505b', fontSize: 11, marginBottom: 4 },
  idCard: { borderWidth: 1, borderColor: '#1c2731', borderRadius: 12, padding: 14, marginBottom: 12, backgroundColor: '#0e1620' },
  idCardHead: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  idCardLogo: { width: 38, height: 38, borderRadius: 10 },
  idCardKicker: { color: '#5a6b76', fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 3 },
  idCardId: { color: '#7cf4c8', fontSize: 17, fontWeight: '800', letterSpacing: 0.5 },
  idCardCopy: { color: '#7cf4c8', fontSize: 12, fontWeight: '800', paddingHorizontal: 8, paddingVertical: 6 },
  idCardLine: { color: '#5a6b76', fontSize: 11, marginTop: 6 },
  idRow: { flexDirection: 'row', alignItems: 'center', borderWidth: 1, borderColor: '#1c2731', borderRadius: 12, padding: 13, marginBottom: 8, backgroundColor: '#0e1620' },
  idRowTitle: { color: '#d5e3dd', fontSize: 14, fontWeight: '700', marginBottom: 3 },
  idRowSub: { color: '#5a6b76', fontSize: 11, lineHeight: 15 },
  idRowArrow: { color: '#5a6b76', fontSize: 15, marginLeft: 10 },
});
