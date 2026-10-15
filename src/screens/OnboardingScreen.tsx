import React, { useState } from 'react';
import { View, Text, TouchableOpacity, ScrollView, StyleSheet, TextInput } from 'react-native';
import { useThemedPrompt } from './ThemedPrompt';
import {
  type VeilSettings, BURN_OPTIONS, EXPIRY_OPTIONS, QUIET_OPTIONS,
  SELF_DESTRUCT_HOURS, SELF_DESTRUCT_WARN_HOURS,
} from '../../vendor/device/src/settings';

/**
 * NATIVE-PARITY-HANDOFF §1 — onboarding flow, exact order & wording:
 *   1. Four intro screens (a)-(d)
 *   2. Privacy Checkup — guided, mandatory while open; every screen answered;
 *      answers ARE the configuration (no presets, no recommendations applied)
 *   3. Veil ID + nickname step — shows the device's Veil ID, collects a
 *      device-local nickname (never transmitted/synced/server-stored)
 *
 * introOnly: replays just the four intro screens ("View the introduction").
 * checkupOnly: opens straight at the Privacy Checkup (Settings → Run the
 * privacy checkup; also the "Secure your VEIL" prompt).
 */

const INTROS = [
  {
    // b117 (owner-approved, Sept 22): matches the b116 login disclaimer —
    // one one-time email opens the relay door; it is never the identity.
    title: 'One email, once, to open the door. Your 24 words are your identity.',
    body: 'Your identity and keys are created on this device and derived from your recovery phrase. The one-time email only opens the message relay — the server holds it only as the login anchor, and it is never connected to your message, contact, note or vault contents.',
  },
  {
    title: 'Private conversations and personal information, under your control.',
    body: 'VEIL keeps conversations between you and the people you speak with. Everything here is yours to control.',
  },
  {
    title: 'One mode. Every control is yours.',
    body: 'After the TestFlight stage, VEIL becomes a one-time payment of A$14.99 — never pay again. Nothing is pre-set: you set every protection yourself.',
  },
  {
    title: 'Confirm who you are speaking with.',
    body: 'Before messages can be sent, a verification code is compared out-of-band so you know the conversation is with the right person.',
  },
  {
    title: 'Understand the limits.',
    body: 'VEIL cannot prevent someone photographing the screen, or access that happens on an unlocked or compromised device.',
  },
];

interface DialStep {
  // b133: keys MUST be REAL VeilSettings field names — answers are spread
  // verbatim into settings at finish ({...settings, ...a}); a key that is
  // not a real field is silently discarded by mergeSettings' clamp and the
  // dial falls back to its default (owner repro Sept 27: chose "5 min" burn
  // in onboarding, settings kept the 7200 fallback, lounge created at 2h).
  key: 'burnTtlSeconds' | 'expireAfterSeconds' | 'retentionHours' | 'localHistory' | 'storageMode' | 'holdUntilUnlock' | 'selfDestruct' | 'readReceipts';
  title: string;
  desc: string;
  defends: string;
  options: { label: string; value: number | boolean | string }[];
}

const DIALS: DialStep[] = [
  {
    key: 'burnTtlSeconds', title: 'Burn after opening',
    desc: 'Messages delete themselves this long after the recipient reads them. Off = threads never burn after opening; messages last their full unopened-expiry window.',
    defends: 'Defends against: someone later opening the device and re-reading conversations.',
    options: BURN_OPTIONS.map((o) => ({ label: o.label + (o.value === 7200 ? '  (Recommended)' : ''), value: o.value })),
  },
  {
    key: 'expireAfterSeconds', title: 'Unopened messages expire',
    desc: 'A message nobody opens is deleted from the relay this long after sending. 36 h is the relay\u2019s hard cap. Off = unopened copies live until the thread ends.',
    defends: 'Defends against: unopened messages accumulating on the relay.',
    options: EXPIRY_OPTIONS.map((o) => ({ label: o.label + (o.value === 86400 ? '  (Recommended)' : ''), value: o.value })),
  },
  {
    key: 'retentionHours', title: 'End quiet threads after',
    desc: 'A conversation with no messages for this long ends and deletes itself on the relay. Off = never ended automatically (the relay still removes records abandoned for a year).',
    defends: 'Defends against: old conversations lingering on the relay.',
    options: QUIET_OPTIONS.map((o) => ({ label: o.label + (o.value === 168 ? '  (Recommended)' : ''), value: o.value })),
  },
  {
    key: 'localHistory', title: 'Keep conversation history on this device',
    desc: 'An encrypted local copy of chats so they survive a reload. Off = closing VEIL forgets the conversation locally.',
    defends: 'Defends against: convenience costing you recovery. Nothing-at-Rest forces this off.',
    options: [{ label: 'On  (Recommended)', value: true }, { label: 'Off', value: false }],
  },
  {
    key: 'storageMode', title: 'Key storage',
    desc: 'Sealed-at-rest keeps conversation keys encrypted on this device. Nothing-at-Rest holds keys in memory only, nothing written to the device — it forces local history off.',
    defends: 'Defends against: keys being extracted from a seized device.',
    options: [{ label: 'Sealed-at-rest  (Recommended)', value: 'device' }, { label: 'Nothing-at-Rest', value: 'memory' }],
  },
  {
    key: 'holdUntilUnlock', title: 'Hold until unlock',
    desc: 'Delivery is held while the phone is locked — a locked phone holds no message data at all.',
    defends: 'Defends against: message data arriving while the device is unattended.',
    options: [{ label: 'On', value: true }, { label: 'Off  (Recommended)', value: false }],
  },
  {
    key: 'selfDestruct', title: 'Self-destruct countdown',
    desc: `Everything VEIL keeps on the device wipes on a fixed ${SELF_DESTRUCT_HOURS}-hour clock; messaging does not reset it. A warning appears ${SELF_DESTRUCT_HOURS - SELF_DESTRUCT_WARN_HOURS} hours before, extendable by another ${SELF_DESTRUCT_HOURS} h. Opt-in — never armed silently by setup.`,
    defends: 'Defends against: a device being kept and inspected later.',
    options: [{ label: 'Off  (Recommended)', value: false }, { label: 'On — wipe everything after 48 hours', value: true }],
  },
  {
    key: 'readReceipts', title: 'Read receipts',
    desc: 'Confirm to the sender when you have read a message. Separate switch — also available in Settings under Messages.',
    defends: 'Defends against: your reading activity being reported without consent.',
    options: [{ label: 'On  (Recommended)', value: true }, { label: 'Off', value: false }],
  },
];

export interface OnboardingScreenProps {
  settings: VeilSettings;
  onApply: (s: VeilSettings) => void;
  onDone: () => void;
  veilId?: string | null;
  mode?: 'full' | 'introOnly' | 'checkupOnly' | 'idOnly';
  /** (b67) passcode is mandatory at the end of the privacy setup */
  appLockEnabled?: boolean;
  onSetAppLock?: (pass: string, decoy?: string | null, duress?: string | null) => Promise<void>;
  /** exit without applying (only rendered for introOnly / checkupOnly —
   *  the checkup opened from Settings must never trap the user) */
  onCancel?: () => void;
}

export function OnboardingScreen({ settings, onApply, onDone, veilId, mode = 'full', onCancel, appLockEnabled, onSetAppLock }: OnboardingScreenProps) {
  // step: 0-3 intros, 4..4+DIALS-1 checkup dials, last = Veil ID + nickname
  const [step, setStep] = useState(mode === 'checkupOnly' ? 4 : mode === 'idOnly' ? 4 + DIALS.length : 0);
  const [answers, setAnswers] = useState<Partial<VeilSettings>>({});
  const [nickname, setNickname] = useState(settings.nickname ?? '');
  const [selfDestructArmed, setSelfDestructArmed] = useState(0);
  // (b67) mandatory passcode at the end of privacy setup (full + checkupOnly)
  const { node: promptNode, ask } = useThemedPrompt();
  const passRequired = (mode === 'full' || mode === 'checkupOnly') && !appLockEnabled;
  const [passSet, setPassSet] = useState(false);
  const [passBusy, setPassBusy] = useState(false);

  const choosePasscode = async () => {
    if (!onSetAppLock || passBusy) return;
    setPassBusy(true);
    try {
      const pass = (await ask({
        title: 'Set your passcode',
        message: 'At least 4 digits. Required to finish privacy setup — it locks VEIL on this device.',
        input: 'secure', numeric: true, submitLabel: 'Next',
      })) as string | null;
      if (!pass) return;
      if (pass.length < 4) { await ask({ title: 'Passcode too short', message: 'Use at least 4 digits.', info: true }); return; }
      const decoy = (await ask({
        title: 'Decoy code (optional)',
        message: 'Cancel to skip. Opens a harmless empty environment if entered at the lock screen.',
        input: 'secure', numeric: true, submitLabel: 'Next',
      })) as string | null;
      const duress = (await ask({
        title: 'Duress code (optional)',
        message: 'Cancel to skip. Best-effort deletion of VEIL data if entered at the lock screen.',
        input: 'secure', numeric: true, submitLabel: 'Save',
      })) as string | null;
      await onSetAppLock(pass, decoy || null, duress || null);
      setPassSet(true);
    } catch (e) {
      await ask({ title: 'Could not save the passcode', message: String((e as Error).message || e), info: true });
    } finally { setPassBusy(false); }
  };
  const last = 4 + DIALS.length;
  const introDone = mode === 'introOnly' ? () => onDone() : () => setStep(4);
  const total = mode === 'introOnly' ? 4 : last + 1;
  // idOnly: straight to the Veil ID + nickname step, no checkup required

  const cancelChip = onCancel && (mode === 'introOnly' || mode === 'checkupOnly') ? (
    <TouchableOpacity style={styles.cancelBtn} onPress={onCancel}>
      <Text style={styles.cancelTxt}>Cancel</Text>
    </TouchableOpacity>
  ) : null;

  if (step < 4) {
    const it = INTROS[step];
    return (
      <View style={styles.fill}>
        {cancelChip}
        <View style={styles.progress}>
          {INTROS.map((_, i) => (
            <View key={i} style={[styles.dot, step >= i && styles.dotOn]} />
          ))}
        </View>
        <Text style={styles.title}>{it.title}</Text>
        <Text style={styles.body}>{it.body}</Text>
        <TouchableOpacity style={styles.btn} onPress={() => (step === 3 ? introDone() : setStep(step + 1))}>
          <Text style={styles.btnTxt}>{step === 3 ? 'Continue' : 'Continue'}</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (step < last) {
    const d = DIALS[step - 4];
    return (
      <View style={styles.fill}>
        {cancelChip}
        <View style={styles.progress}>
          {Array.from({ length: total - 4 }).map((_, i) => (
            <View key={i} style={[styles.dot, step - 4 >= i && styles.dotOn]} />
          ))}
        </View>
        <ScrollView style={styles.scroll} contentContainerStyle={{ paddingBottom: 120 }}>
          <Text style={styles.kicker}>Privacy Checkup</Text>
          <Text style={styles.title}>{d.title}</Text>
          <Text style={styles.body}>{d.desc}</Text>
          <Text style={styles.defends}>{d.defends}</Text>
          {d.options.map((o) => (
            <TouchableOpacity
              key={String(o.value)}
              style={[styles.opt, answers[d.key as keyof VeilSettings] === o.value && styles.optOn]}
              onPress={() => {
                setAnswers((a) => {
                  const next = { ...a, [d.key]: o.value } as Partial<VeilSettings>;
                  if (d.key === 'storageMode' && o.value === 'memory') next.localHistory = false;
                  if (d.key === 'selfDestruct') setSelfDestructArmed(o.value === true ? Date.now() : 0);
                  return next;
                });
                setStep(step + 1);
              }}
            >
              <Text style={[styles.optTxt, answers[d.key as keyof VeilSettings] === o.value && styles.optTxtOn]}>{o.label}</Text>
            </TouchableOpacity>
          ))}
          {step > 4 ? (
            <TouchableOpacity onPress={() => setStep(step - 1)}>
              <Text style={styles.back}>Back</Text>
            </TouchableOpacity>
          ) : null}
        </ScrollView>
      </View>
    );
  }

  // Veil ID + nickname step
  const canFinish = !passRequired || passSet;
  return (
    <View style={styles.fill}>
      {promptNode}
      {cancelChip}
      <ScrollView style={styles.scroll} contentContainerStyle={{ paddingBottom: 60, flexGrow: 1, justifyContent: 'center' }}>
        <View style={styles.progress}>
          {Array.from({ length: total }).map((_, i) => (
            <View key={i} style={[styles.dot, i <= last && styles.dotOn]} />
          ))}
        </View>
        <Text style={styles.title}>Your Veil ID</Text>
        <Text style={styles.idText}>{veilId ?? 'Your identity will publish a Veil ID shortly.'}</Text>
        <Text style={styles.body}>Share your Veil ID with people you want to speak with. They use it to look you up and verify they are speaking with you.</Text>
        <Text style={styles.label}>Nickname for this device (local only)</Text>
        <TextInput
          style={styles.input}
          value={nickname}
          onChangeText={setNickname}
          placeholder="Optional — never leaves this device"
          placeholderTextColor="#3a4a54"
        />
        {passRequired ? (
          <View style={styles.passBox}>
            <Text style={styles.passTitle}>{passSet ? 'Passcode set ✓' : 'Set your passcode — required to finish'}</Text>
            <Text style={styles.passHint}>
              {passSet
                ? 'VEIL will now lock behind your passcode whenever it is opened.'
                : 'Privacy setup is not complete until this device is protected by a passcode. It locks VEIL whenever the app is opened or left.'}
            </Text>
            {!passSet ? (
              <TouchableOpacity style={styles.passBtn} onPress={choosePasscode} disabled={passBusy}>
                <Text style={styles.passBtnTxt}>{passBusy ? '…' : 'Choose a passcode'}</Text>
              </TouchableOpacity>
            ) : null}
          </View>
        ) : null}
        <TouchableOpacity
          style={[styles.btn, !canFinish && styles.btnOff]}
          disabled={!canFinish}
          onPress={() => {
            const a = answers;
            onApply({
              ...settings,
              ...a,
              nickname,
              selfDestructArmedAt: a.selfDestruct === true ? selfDestructArmed || Date.now() : 0,
              setupDone: true,
            } as VeilSettings);
            onDone();
          }}
        >
          <Text style={styles.btnTxt}>Apply these settings</Text>
        </TouchableOpacity>
        {!canFinish ? <Text style={styles.gateNote}>Choose a passcode above to finish.</Text> : null}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0b0f14', padding: 26, justifyContent: 'center' },
  scroll: { flex: 1 },
  progress: { flexDirection: 'row', gap: 6, justifyContent: 'center', marginBottom: 26 },
  dot: { width: 8, height: 8, borderRadius: 4, borderWidth: 1, borderColor: '#2a3b46' },
  dotOn: { backgroundColor: '#7cf4c8', borderColor: '#7cf4c8' },
  kicker: { color: '#5a6b76', fontSize: 11, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 10 },
  title: { color: '#d7e2e8', fontSize: 20, fontWeight: '700', marginBottom: 12, textAlign: 'center' },
  body: { color: '#7a8b96', fontSize: 13, lineHeight: 19, marginBottom: 12, textAlign: 'center' },
  defends: { color: '#5a6b76', fontSize: 11, lineHeight: 16, marginBottom: 18, textAlign: 'center', fontStyle: 'italic' },
  opt: { borderWidth: 1, borderColor: '#1b2a35', borderRadius: 10, padding: 14, marginBottom: 8 },
  optOn: { borderColor: '#7cf4c8', backgroundColor: 'rgba(124,244,200,0.06)' },
  optTxt: { color: '#cfe3dd', fontSize: 14 },
  optTxtOn: { color: '#7cf4c8', fontWeight: '700' },
  back: { color: '#5a6b76', fontSize: 12, textAlign: 'center', marginTop: 14 },
  btn: { backgroundColor: '#7cf4c8', borderRadius: 22, paddingVertical: 14, alignItems: 'center', marginTop: 18 },
  btnTxt: { color: '#06231c', fontWeight: '800', fontSize: 14 },
  idText: { color: '#7cf4c8', fontSize: 16, fontWeight: '700', textAlign: 'center', marginBottom: 12, letterSpacing: 1 },
  label: { color: '#7a8b96', fontSize: 12, marginBottom: 6 },
  input: { borderWidth: 1, borderColor: '#1b2a35', borderRadius: 10, color: '#d7e2e8', padding: 12, fontSize: 14, marginBottom: 6 },
  passBox: { borderWidth: 1, borderColor: '#7cf4c8', borderRadius: 12, padding: 14, marginVertical: 12, backgroundColor: 'rgba(124,244,200,0.05)' },
  passTitle: { color: '#7cf4c8', fontSize: 13, fontWeight: '800', marginBottom: 6 },
  passHint: { color: '#7a8b96', fontSize: 12, lineHeight: 17, marginBottom: 10 },
  passBtn: { backgroundColor: '#7cf4c8', borderRadius: 10, paddingVertical: 12, alignItems: 'center' },
  passBtnTxt: { color: '#06231c', fontWeight: '800', fontSize: 13 },
  btnOff: { backgroundColor: '#2a3b46' },
  gateNote: { color: '#5a6b76', fontSize: 11, textAlign: 'center', marginTop: 8 },
  cancelBtn: { position: 'absolute', top: 54, right: 24, zIndex: 10, paddingHorizontal: 14, paddingVertical: 8, borderRadius: 16, borderWidth: 1, borderColor: '#2a3b46' },
  cancelTxt: { color: '#5a6b76', fontSize: 13, fontWeight: '600' },
});
