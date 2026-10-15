import React, { useEffect, useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, Image } from 'react-native';

/**
 * Lock screen. Two web-parity paths:
 *  - app lock configured: numeric keypad first (passcode / Decoy / Duress)
 *  - otherwise: biometric unlock button (native setup flow)
 */

export function LockScreen({
  hint, onUnlock, onCode, hasAppLock, codeError, verifying, resetKey, lockoutUntil,
}: {
  onUnlock: () => void;
  hint: string | null;
  onCode: (code: string) => void;
  hasAppLock: boolean;
  codeError: string | null;
  /** true while the 210k-iteration PBKDF2 check runs — keypad disabled, spinner shown */
  verifying?: boolean;
  /** parent bumps this (e.g. Date.now()) to clear the entered digits after a wrong code */
  resetKey?: number;
  /** b123: epoch ms until which the keypad is dead (5 wrong attempts ->
   *  progressive lockout). 0/undefined = no active lockout. */
  lockoutUntil?: number;
}) {
  const [code, setCode] = useState('');
  useEffect(() => { setCode(''); }, [resetKey]);
  // b123: live countdown while a lockout is running; the keypad re-enables
  // itself the moment the window expires.
  const [now, setNow] = useState(Date.now());
  const active = !!lockoutUntil && lockoutUntil > now;
  useEffect(() => {
    if (!lockoutUntil) return;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [lockoutUntil]);
  const waitMins = active && lockoutUntil
    ? Math.max(1, Math.ceil((lockoutUntil - now) / 60_000))
    : 0;
  const blocked = verifying || active;
  const press = (d: string) => setCode((c) => (blocked || c.length >= 12 ? c : c + d));

  return (
    <View style={styles.fill}>
      {/* b109 (owner request Sept 22): the bare ARCS above the wordmark —
          logo-mark.png is the transparent ring/arc mark, no square plate. */}
      <Image source={require('../../assets/logo-mark.png')} style={styles.logo} resizeMode="contain" />
      <Text style={styles.wordmark}>VEIL</Text>
      {hasAppLock ? (
        <>
          <Text style={styles.locked}>Veil is locked</Text>
          <Text style={styles.hint}>{hint ?? 'Enter your passcode to unlock.'}</Text>
          <View style={styles.dots}>
            {Array.from({ length: Math.max(6, code.length) }).map((_, i) => (
              <View key={i} style={[styles.dot, code.length > i && styles.dotOn]} />
            ))}
          </View>
          {active ? (
            <Text style={styles.lockoutTxt}>Too many incorrect attempts — try again in {waitMins} min.</Text>
          ) : (
            <Text style={styles.err}>{verifying ? 'Verifying — this takes a few seconds on this device.' : (codeError ?? '')}</Text>
          )}
          <View style={styles.pad}>
            {['1', '2', '3', '4', '5', '6', '7', '8', '9'].map((d) => (
              <TouchableOpacity key={d} style={styles.key} onPress={() => press(d)}>
                <Text style={styles.keyTxt}>{d}</Text>
              </TouchableOpacity>
            ))}
            <TouchableOpacity style={[styles.key, blocked && styles.keyBusy]} disabled={blocked} onPress={() => setCode('')}>
              <Text style={styles.keyDel}>C</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.key} onPress={() => press('0')}>
              <Text style={styles.keyTxt}>0</Text>
            </TouchableOpacity>
            <TouchableOpacity style={[styles.key, blocked && styles.keyBusy]} disabled={blocked} onPress={() => setCode((c) => c.slice(0, -1))}>
              <Text style={styles.keyDel}>⌫</Text>
            </TouchableOpacity>
          </View>
          <TouchableOpacity style={[styles.btn, blocked && styles.btnBusy]} disabled={blocked || code.length === 0} onPress={() => onCode(code)}>
            <Text style={styles.btnTxt}>{active ? `Locked · ${waitMins} min` : verifying ? 'Verifying…' : 'Unlock'}</Text>
          </TouchableOpacity>
        </>
      ) : (
        <>
          <Text style={styles.locked}>Veil is locked</Text>
          <Text style={styles.hint}>{hint ?? 'Authenticate to unlock your sessions.'}</Text>
          <TouchableOpacity style={styles.btn} onPress={onUnlock}>
            <Text style={styles.btnTxt}>Unlock</Text>
          </TouchableOpacity>
        </>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  // (b69) owner request: keypad ~5% BIGGER + fully symmetric 4x3 grid (Clear | 0 | ⌫)
  fill: { flex: 1, backgroundColor: '#0b0f14', alignItems: 'center', justifyContent: 'center', padding: 24 },
  logo: { width: 92, height: 92 },
  // letterSpacing adds a trailing gap after the final glyph — nudge the
  // wordmark right by half so "VEIL" sits dead-center optically, not the
  // measured box.
  wordmark: { color: '#7cf4c8', fontSize: 37, fontWeight: '800', letterSpacing: 16, marginTop: 14, marginLeft: 8 },
  locked: { color: '#d7e2e8', fontSize: 16, marginTop: 22 },
  hint: { color: '#41505b', fontSize: 13, marginTop: 6, marginBottom: 18, textAlign: 'center' },
  dots: { flexDirection: 'row', gap: 12, marginBottom: 6 },
  dot: { width: 14, height: 14, borderRadius: 7, borderWidth: 1, borderColor: '#2a3b46' },
  dotOn: { backgroundColor: '#7cf4c8', borderColor: '#7cf4c8' },
  err: { color: '#e8836f', fontSize: 13, height: 20, textAlign: 'center' },
  // b123: lockout banner — teal-accent alert, sized to replace the error line
  lockoutTxt: { color: '#7cf4c8', fontSize: 13, height: 20, textAlign: 'center', fontWeight: '700' },
  pad: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'center', width: 255, marginVertical: 8 },
  key: { width: 77, height: 61, alignItems: 'center', justifyContent: 'center', borderRadius: 12, margin: 4, borderWidth: 1, borderColor: '#1b2a35' },
    keyTxt: { color: '#cfe3dd', fontSize: 22, fontWeight: '600' },
  keyDel: { color: '#5a6b76', fontSize: 20 },
  keyBusy: { opacity: 0.4 },
  btn: { backgroundColor: '#7cf4c8', borderRadius: 24, paddingHorizontal: 52, paddingVertical: 15, marginTop: 16 },
  btnBusy: { backgroundColor: '#2a3b46' },
  btnTxt: { color: '#06231c', fontWeight: '800', fontSize: 15 },
});
