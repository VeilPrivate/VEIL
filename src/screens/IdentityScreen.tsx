import React, { useEffect, useMemo, useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, Platform, ActivityIndicator, Image, Alert} from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';



export interface IdentityScreenProps {
  /** Provision a freshly created identity (create flow). */
  onCreate: () => Promise<{ phrase: string[]; veilId: string }>;
  /** Restore an existing identity from its 24-word phrase. */
  onRestore: (phrase: string) => Promise<void>;
  /** Provision the freshly created identity (called after the user confirms the phrase is written down). */
  onFinishCreate: () => Promise<void>;
  /** Sign out and go back to login. */
  onSignOut: () => void;
  /** b112: classic email sign-in for existing accounts (the account link). */
  onAccountSignIn?: () => void;
  /** Entry point — 'confirm-create' for Settings > "Generate new Veil ID" (skips the chooser). */
  initialMode?: 'choose' | 'confirm-create';
}

/**
 * Shown after login when the device keychain holds no Veil identity.
 * Restore (phrase login) or create a new anonymous identity.
 * The phrase and keys never leave the device in either flow.
 */

/**
 * b111 (owner directive: no raw internal errors on screen, ever): raw
 * exception text goes to the Metro console; the UI gets one human sentence.
 */
function friendlyError(e: unknown, what: string): string {
  const err = e as Error;
  console.log(`[veil-error] ${what}:`, String(err?.message ?? e), err?.stack ?? '');
  const s = String(err?.message ?? e).toLowerCase();
  if (s.includes('network') || s.includes('timeout') || s.includes('fetch') || s.includes('request failed'))
    return 'Connection problem — check your internet and try again.';
  if (s.includes('permission') || s.includes('denied') || s.includes('not authorized'))
    return 'A permission was declined — check VEIL in iPhone Settings, then try again.';
  if (s.includes('rate limit'))
    // b175 (owner Metro repro, Oct 2: burst send surfaced a raw-feeling
    // "Something went wrong" during a transient relay throttle): the relay's
    // anti-abuse limiter is a few-second self-healing cooldown, not a real
    // failure — say so plainly instead of falling through to the scary
    // generic bucket. The composer keeps the drafted text either way.
    return 'The server is briefly busy — wait a few seconds and try again.';
  return 'Something went wrong — please try again.';
}

export function IdentityScreen({ onCreate, onRestore, onFinishCreate, onSignOut, onAccountSignIn, initialMode = 'choose' }: IdentityScreenProps) {
  const kbH = useKbPadding();
  const [mode, setMode] = useState<'choose' | 'restore' | 'confirm-create' | 'reveal' | 'provisioning'>(initialMode);
  const [phraseInput, setPhraseInput] = useState('');
  const [words, setWords] = useState<string[]>([]);
  // b168 (web P3.8 parity): the phrase is hidden until the user deliberately
  // taps "Show my 24 words" — no accidental shoulder-surf reveal the instant
  // keys are generated. Reset for each fresh creation.
  const [revealed, setRevealed] = useState(false);
  const [written, setWritten] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const wordCount = useMemo(() => phraseInput.trim().split(/\s+/).filter(Boolean).length, [phraseInput]);

  const doCreate = async () => {
    setBusy(true); setError(null);
    try {
      const { phrase } = await onCreate();
      setRevealed(false);
      setWords(phrase);
      setMode('reveal');
      setWritten(false);
    } catch (e) {
      const msg = String((e as Error).message || e) + '\n\n' + String((e as Error).stack || '').slice(0, 400);
      setError(msg);
      try { Alert.alert('VEIL error — photograph this screen', msg); } catch { /* Alert optional */ }
    } finally { setBusy(false); }
  };

  const doRestore = async () => {
    setBusy(true); setError(null);
    try {
      await onRestore(phraseInput.trim().toLowerCase());
    } catch (e) {
      setError(friendlyError(e, 'identity'));
      setBusy(false);
    }
  };

  const header = (
    <View style={styles.brand}>
      <Image source={require('../../assets/logo.png')} style={styles.logoMark} />
      <Text style={styles.logo}>VEIL</Text>
    </View>
  );

  if (mode === 'choose') {
    return (
      <View style={styles.fill}>
        <ScrollView contentContainerStyle={[styles.scroll, kbH > 0 ? { paddingBottom: kbH + 24 } : null]}>
          {header}
          <Text style={styles.h1}>One last thing</Text>
          <Text style={styles.h2}>
            This device has no Veil identity. Your identity is a veil-id — a public key with no name, email or phone number attached.
          </Text>

          <TouchableOpacity style={styles.card} onPress={() => setMode('restore')} disabled={busy}>
            <Text style={styles.cardTitle}>Restore with recovery phrase</Text>
            <Text style={styles.cardBody}>Have your 24 words? Your identity, contacts and pins come back on this device.</Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.cardTeal} onPress={() => setMode('confirm-create')} disabled={busy}>
            <Text style={styles.cardTealTitle}>Create a new identity</Text>
            <Text style={styles.cardTealBody}>Generates a fresh veil-id and a one-time 24-word phrase.</Text>
          </TouchableOpacity>

          {error ? <Text style={styles.error}>{error}</Text> : null}
          {onAccountSignIn ? (
            <TouchableOpacity style={styles.link} onPress={onAccountSignIn} disabled={busy}>
              <Text style={styles.linkText}>Sign in with an existing account</Text>
            </TouchableOpacity>
          ) : null}
          <TouchableOpacity style={styles.link} onPress={onSignOut} disabled={busy}>
            <Text style={styles.linkText}>Sign out</Text>
          </TouchableOpacity>
        </ScrollView>
      </View>
    );
  }

  if (mode === 'restore') {
    return (
      <View style={styles.fill}>
        <ScrollView contentContainerStyle={[styles.scroll, kbH > 0 ? { paddingBottom: kbH + 24 } : null]} keyboardShouldPersistTaps="handled">
          {header}
          <Text style={styles.h1}>Recovery phrase</Text>
          <Text style={styles.h2}>
            Type or paste your 24 words, in order, separated by spaces. The phrase is checked on this device first — a phrase from another identity is rejected before anything reaches the network.
          </Text>

          <TextInput
            style={[styles.input, wordCount === 24 && styles.inputOk]}
            multiline
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="word word word …"
            placeholderTextColor="#3b4b56"
            value={phraseInput}
            editable={!busy}
            onChangeText={(t) => { setPhraseInput(t.toLowerCase()); setError(null); }}
          />
          <Text style={[styles.counter, wordCount === 24 && styles.counterOk]}>{wordCount} / 24 words</Text>

          {error ? <Text style={styles.error}>{error}</Text> : null}

          {busy ? (
            <ActivityIndicator color="#5fd4c4" style={styles.busy} />
          ) : (
            <TouchableOpacity
              style={[styles.cta, wordCount !== 24 && styles.ctaDisabled]}
              disabled={wordCount !== 24}
              onPress={doRestore}
            >
              <Text style={styles.ctaText}>Restore identity</Text>
            </TouchableOpacity>
          )}

          <TouchableOpacity style={styles.link} onPress={() => setMode('choose')} disabled={busy}>
            <Text style={styles.linkText}>← Other options</Text>
          </TouchableOpacity>
        </ScrollView>
      </View>
    );
  }

  if (mode === 'confirm-create') {
    return (
      <View style={styles.fill}>
        <ScrollView contentContainerStyle={[styles.scroll, kbH > 0 ? { paddingBottom: kbH + 24 } : null]}>
          {header}
          <Text style={styles.h1}>Create a new identity?</Text>
          <Text style={styles.h2}>
            A new veil-id is generated on this device. You will get a 24-word recovery phrase shown exactly once — if you lose it, the identity is gone forever. No one, including us, can recover it for you.
          </Text>
          <TouchableOpacity style={styles.cta} onPress={doCreate} disabled={busy}>
            <Text style={styles.ctaText}>{busy ? 'Generating…' : 'Yes — create my identity'}</Text>
          </TouchableOpacity>
          {error ? <Text style={styles.error}>{error}</Text> : null}
          <TouchableOpacity style={styles.link} onPress={() => setMode('choose')} disabled={busy}>
            <Text style={styles.linkText}>← Back</Text>
          </TouchableOpacity>
        </ScrollView>
      </View>
    );
  }

  if (mode === 'reveal') {
    return (
      <ScrollView style={styles.fill} contentContainerStyle={styles.scroll}>
        {header}
        <Text style={styles.h1}>Your recovery phrase</Text>
        {!revealed ? (
          <>
            {/* b168 (web P3.8 parity): announce the 24-word requirement and
                prep the user BEFORE the words hit the screen — the phrase only
                appears behind a deliberate "Show my 24 words" tap. */}
            <Text style={styles.h2}>
              Your identity comes with a 24-word recovery phrase. It is the only way to restore this identity, and it is shown exactly once — no one, including us, can recover it for you.
            </Text>
            <Text style={styles.h2}>
              Get paper and a pen ready. Make sure no one can see your screen, then reveal the words.
            </Text>
            <TouchableOpacity style={styles.cta} onPress={() => setRevealed(true)}>
              <Text style={styles.ctaText}>Show my 24 words</Text>
            </TouchableOpacity>
            {error ? <Text style={styles.error}>{error}</Text> : null}
          </>
        ) : (
          <>
            <Text style={styles.h2}>
              Write these 24 words down, in order, on paper. They are the only way to restore this identity. They are never shown again.
            </Text>

            <View style={styles.wordGrid}>
          {words.map((w, i) => (
            <View key={i} style={styles.wordRow}>
              <Text style={styles.wordNum}>{i + 1}</Text>
              <Text style={styles.word}>{w}</Text>
            </View>
          ))}
        </View>

            <TouchableOpacity style={styles.check} onPress={() => setWritten(!written)}>
              <View style={[styles.checkbox, written && styles.checkboxOn]} />
              <Text style={styles.checkText}>I have written it down somewhere safe</Text>
            </TouchableOpacity>

            {busy ? (
              <ActivityIndicator color="#5fd4c4" style={styles.busy} />
            ) : (
              <TouchableOpacity
                style={[styles.cta, !written && styles.ctaDisabled]}
                disabled={!written || busy}
                onPress={async () => {
                  setBusy(true); setError(null);
                  try { await onFinishCreate(); } catch (e) { setError(friendlyError(e, 'identity')); setBusy(false); }
                }}
              >
                <Text style={styles.ctaText}>Finish</Text>
              </TouchableOpacity>
            )}
            {error ? <Text style={styles.error}>{error}</Text> : null}
          </>
        )}
      </ScrollView>
    );
  }

  return (
    <View style={[styles.fill, styles.center]}>
      <ActivityIndicator color="#5fd4c4" />
      <Text style={styles.bootText}>Sealing your identity…</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0b0f14' },
  scroll: { padding: 28 },
  center: { alignItems: 'center', justifyContent: 'center' },
  brand: { alignItems: 'center', marginBottom: 30, marginTop: 10 },
  logoMark: { width: 60, height: 60, marginBottom: 12 },
  logo: { color: '#7cf4c8', fontSize: 28, fontWeight: '700', letterSpacing: 8 },
  h1: { color: '#e6eef2', fontSize: 22, fontWeight: '600' },
  h2: { color: '#5a6b76', fontSize: 13, marginTop: 8, marginBottom: 20, lineHeight: 19 },
  card: { backgroundColor: '#111820', borderRadius: 14, borderWidth: 1, borderColor: '#1d2a33', padding: 18, marginBottom: 14 },
  cardTitle: { color: '#e6eef2', fontSize: 16, fontWeight: '600' },
  cardBody: { color: '#5a6b76', fontSize: 12, marginTop: 6, lineHeight: 17 },
  cardTeal: { backgroundColor: '#0d1f1c', borderRadius: 14, borderWidth: 1, borderColor: '#1f4a42', padding: 18, marginBottom: 14 },
  cardTealTitle: { color: '#5fd4c4', fontSize: 16, fontWeight: '600' },
  cardTealBody: { color: '#5a6b76', fontSize: 12, marginTop: 6, lineHeight: 17 },
  input: {
    color: '#e6eef2', backgroundColor: '#0b0f14', borderWidth: 1, borderColor: '#223039',
    borderRadius: 10, padding: 14, fontSize: 16, minHeight: 120, textAlignVertical: 'top',
  },
  inputOk: { borderColor: '#1f4a42' },
  counter: { color: '#41505b', fontSize: 12, marginTop: 6, marginBottom: 16 },
  counterOk: { color: '#5fd4c4' },
  wordGrid: { backgroundColor: '#111820', borderRadius: 14, borderWidth: 1, borderColor: '#1d2a33', padding: 14 },
  wordRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 4 },
  wordNum: { color: '#41505b', fontSize: 11, width: 26 },
  word: { color: '#e6eef2', fontSize: 14, letterSpacing: 0.5 },
  check: { flexDirection: 'row', alignItems: 'center', marginTop: 18, marginBottom: 22 },
  checkbox: { width: 22, height: 22, borderRadius: 6, borderWidth: 1.5, borderColor: '#3b4b56', marginRight: 10 },
  checkboxOn: { backgroundColor: '#5fd4c4', borderColor: '#5fd4c4' },
  checkText: { color: '#8aa0ad', fontSize: 13, flexShrink: 1 },
  cta: { backgroundColor: '#5fd4c4', borderRadius: 10, padding: 15, alignItems: 'center' },
  ctaDisabled: { opacity: 0.35 },
  ctaText: { color: '#062019', fontSize: 16, fontWeight: '700' },
  busy: { marginTop: 14 },
  link: { alignItems: 'center', marginTop: 18 },
  linkText: { color: '#5fd4c4', fontSize: 13 },
  error: { color: '#ff8f8f', fontSize: 13, marginTop: 10, lineHeight: 18 },
  bootText: { color: '#5a6b76', marginTop: 14, fontSize: 13, letterSpacing: 1 },
});
