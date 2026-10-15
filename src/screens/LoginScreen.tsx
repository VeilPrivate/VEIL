import React, { useEffect, useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Image, Platform, ActivityIndicator, ScrollView} from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';



export interface LoginScreenProps {
  busy: boolean;
  error: string | null;
  info: string | null;
  onLogin: (email: string, password: string) => void;
  onForgotPassword: (email: string) => void;
  onSignup: (email: string, password: string) => void;
  /** b112: back to the identity flow (create/restore without an account screen). */
  onSwitchToIdentity?: () => void;
}

/** Account sign-in / sign-up (the Base44 app account — the Veil identity is restored/created after). */
export function LoginScreen({ busy, error, info, onLogin, onForgotPassword, onSignup, onSwitchToIdentity }: LoginScreenProps) {
  const kbH = useKbPadding();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState<'signin' | 'forgot' | 'signup'>('signin');
  const forgot = mode === 'forgot';

  return (
    <View style={styles.fill}>
      <ScrollView contentContainerStyle={[styles.scroll, kbH > 0 ? { paddingBottom: kbH + 24 } : null]} keyboardShouldPersistTaps="handled">
        <View style={styles.brand}>
          <Image source={require('../../assets/logo.png')} style={styles.logoMark} />
          <Text style={styles.logo}>VEIL</Text>
          <Text style={styles.tagline}>Private by design.</Text>
        </View>

        {/* b198 (founder decision, Oct 15): ANONYMOUS SIGNUP — the Base44-era
            verified-email mandate is retired on our own relay. The email is a
            SELF-DECLARED label: real or invented, never verified, never
            contacted. This disclaimer is the first thing a new user reads. */}
        <View style={styles.disclaimer}>
          <Text style={styles.disclaimerTitle}>YOUR EMAIL IS A LABEL — NOT YOUR IDENTITY</Text>
          <Text style={styles.disclaimerBody}>
            Choose any address — real or completely invented (quiet-fox-42@example.com is fine). It is never verified, never contacted, and never shown to anyone you talk to. It only anchors your login.
          </Text>
          <Text style={styles.disclaimerBold}>Your email is not your identity.</Text>
          <View style={styles.disclaimerRow}><Text style={styles.disclaimerDot}>•</Text><Text style={styles.disclaimerItem}>Your VEIL ID, your identity keys and your 24-word phrase are created on this device and never touch the email.</Text></View>
          <View style={styles.disclaimerRow}><Text style={styles.disclaimerDot}>•</Text><Text style={styles.disclaimerItem}>Your messages, contacts, notes and vaults are end-to-end encrypted. This address is only the login anchor — it is never connected to your message, contact, note or vault contents.</Text></View>
          <View style={styles.disclaimerRow}><Text style={styles.disclaimerDot}>•</Text><Text style={styles.disclaimerItem}>The relay only sees sealed envelopes passing between anonymous IDs.</Text></View>
          <Text style={styles.disclaimerBody}>
            A forgotten password cannot be recovered by email — your 24-word phrase is the ONLY way back into your identity. Keep it safe. Once you are in, the email plays no part in how VEIL identifies you, finds you, or talks to your contacts.
          </Text>
        </View>

        <View style={styles.card}>
          <Text style={styles.h1}>{forgot ? 'Reset password' : mode === 'signup' ? 'Create account' : 'Sign in'}</Text>
          <Text style={styles.h2}>
            {forgot
              ? 'Accounts are anonymous — a password cannot be reset or emailed. Sign in with your password, or restore your identity with your 24-word phrase from the welcome screen.'
              : 'Your account keys never leave this device. No email verification — the address is whatever you type.'}
          </Text>

          <Text style={styles.label}>EMAIL</Text>
          <TextInput
            style={styles.input}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="email-address"
            textContentType="emailAddress"
            placeholder="you@example.com"
            placeholderTextColor="#3b4b56"
            value={email}
            editable={!busy}
            onChangeText={setEmail}
          />

          {!forgot && (
            <>
              <Text style={styles.label}>PASSWORD</Text>
              <TextInput
                style={styles.input}
                secureTextEntry
                autoCapitalize="none"
                textContentType="password"
                placeholder="••••••••"
                placeholderTextColor="#3b4b56"
                value={password}
                editable={!busy}
                onChangeText={setPassword}
              />
            </>
          )}

          {error ? <Text style={styles.error}>{error}</Text> : null}
          {info ? <Text style={styles.info}>{info}</Text> : null}

          {busy ? (
            <ActivityIndicator color="#5fd4c4" style={styles.busy} />
          ) : (
            <TouchableOpacity
              style={[styles.cta, (!email || (!forgot && !password)) && styles.ctaDisabled]}
              disabled={!email || (!forgot && !password)}
              onPress={() =>
                forgot
                  ? onForgotPassword(email.trim())
                  : mode === 'signup'
                    ? onSignup(email.trim(), password)
                    : onLogin(email.trim(), password)
              }
            >
              <Text style={styles.ctaText}>{forgot ? 'Email me a reset link' : mode === 'signup' ? 'Create account' : 'Sign in'}</Text>
            </TouchableOpacity>
          )}

          <TouchableOpacity style={styles.link} onPress={() => { setMode(mode === 'forgot' ? 'signin' : 'forgot'); }} disabled={busy}>
            <Text style={styles.linkText}>
              {forgot ? '← Back to sign in' : 'Forgot password?'}
            </Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.link} onPress={() => { setMode(mode === 'signup' ? 'signin' : 'signup'); }} disabled={busy}>
            <Text style={styles.linkText}>
              {mode === 'signup' ? '← I already have an account' : 'New here? Create an account'}
            </Text>
          </TouchableOpacity>

          {onSwitchToIdentity ? (
            <TouchableOpacity style={styles.link} onPress={onSwitchToIdentity} disabled={busy}>
              <Text style={styles.linkText}>← No account needed — create a Veil identity</Text>
            </TouchableOpacity>
          ) : null}
        </View>

        <Text style={styles.footing}>
          No phone number. No contact list. Messages are sealed before they leave the device.
        </Text>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0b0f14' },
  scroll: { flexGrow: 1, justifyContent: 'center', padding: 28 },
  brand: { alignItems: 'center', marginBottom: 36 },
  logoMark: { width: 76, height: 76, marginBottom: 18 },
  logo: { color: '#7cf4c8', fontSize: 40, fontWeight: '700', letterSpacing: 10 },
  tagline: { color: '#5a6b76', marginTop: 10, fontSize: 14, letterSpacing: 1 },
  card: { backgroundColor: '#111820', borderRadius: 16, borderWidth: 1, borderColor: '#1d2a33', padding: 22 },
  h1: { color: '#e6eef2', fontSize: 22, fontWeight: '600' },
  h2: { color: '#5a6b76', fontSize: 13, marginTop: 6, marginBottom: 18, lineHeight: 18 },
  label: { color: '#8aa0ad', fontSize: 11, letterSpacing: 2, marginBottom: 6 },
  input: {
    color: '#e6eef2', backgroundColor: '#0b0f14', borderWidth: 1, borderColor: '#223039',
    borderRadius: 10, padding: 14, fontSize: 16, marginBottom: 16,
  },
  cta: { backgroundColor: '#5fd4c4', borderRadius: 10, padding: 15, alignItems: 'center', marginTop: 4 },
  ctaDisabled: { opacity: 0.35 },
  ctaText: { color: '#062019', fontSize: 16, fontWeight: '700' },
  busy: { marginTop: 14 },
  link: { alignItems: 'center', marginTop: 16 },
  linkText: { color: '#5fd4c4', fontSize: 13 },
  error: { color: '#ff8f8f', fontSize: 13, marginBottom: 10, lineHeight: 18 },
  info: { color: '#8fd9c8', fontSize: 13, marginBottom: 10, lineHeight: 18 },
  footing: { color: '#41505b', fontSize: 11, textAlign: 'center', marginTop: 28, lineHeight: 16 },
  // b116: email disclaimer card — same teal-bordered card language as the
  // Settings sections (b107), with the VEIL message orange for the one
  // line we most need every user to internalise.
  disclaimer: {
    backgroundColor: '#111820', borderRadius: 16, borderWidth: 1, borderColor: '#1f4a42',
    padding: 22, marginBottom: 18,
  },
  disclaimerTitle: { color: '#7cf4c8', fontSize: 12, fontWeight: '700', letterSpacing: 2, marginBottom: 10 },
  disclaimerBody: { color: '#8aa0ad', fontSize: 13, lineHeight: 19, marginBottom: 10 },
  disclaimerBold: { color: '#d69a5c', fontSize: 14, fontWeight: '700', marginBottom: 8 },
  disclaimerRow: { flexDirection: 'row', marginBottom: 6 },
  disclaimerDot: { color: '#5fd4c4', fontSize: 13, lineHeight: 19, marginRight: 8 },
  disclaimerItem: { color: '#8aa0ad', fontSize: 13, lineHeight: 19, flex: 1 },
});
