/**
 * ThemedPrompt — VEIL's replacement for React Native's system Alert.prompt /
 * Alert.alert dialogs (owner request, Sept 19 b57): the OS alerts are plain
 * white iPhone boxes whose text can't match the app theme. This overlay uses
 * the same proven in-screen pattern as the chat preview / image viewer
 * (absolute overlay, NOT RN Modal — the modal/native-picker collision freeze
 * from b25 stays avoided).
 *
 * Usage (one hook per screen):
 *   const { node, ask } = useThemedPrompt();
 *   ... render {node} anywhere in the tree ...
 *   const pw = await ask({ title: 'Unlock vault', secure: true, numeric: true });
 *
 * ask() resolves with:
 *   - input prompts: the typed string, or null when cancelled
 *   - confirm dialogs: true / false
 *   - info notices: true (dismiss)
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet,
  Keyboard, Platform, ActivityIndicator,
} from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';

export interface PromptSpec {
  title: string;
  message?: string;
  /** text input shown when set: 'secure' masks, 'text' is plain */
  input?: 'secure' | 'text';
  placeholder?: string;
  defaultValue?: string;
  numeric?: boolean;
  maxLength?: number;
  submitLabel?: string;
  /** confirm dialog (no input): resolves true/false */
  confirm?: boolean;
  /** info notice (single OK): resolves true */
  info?: boolean;
  /** renders the confirm button in the destructive red */
  danger?: boolean;
  /** spinner state rendered by the caller after submit */
  busy?: boolean;
}

interface ActivePrompt {
  spec: PromptSpec;
  resolve: (v: string | boolean | null) => void;
}

export function useThemedPrompt(): { node: React.ReactNode; ask: (spec: PromptSpec) => Promise<string | boolean | null> } {
  const [active, setActive] = useState<ActivePrompt | null>(null);

  const ask = useCallback((spec: PromptSpec) => {
    return new Promise<string | boolean | null>((resolve) => {
      setActive({ spec, resolve });
    });
  }, []);

  const settle = useCallback((v: string | boolean | null) => {
    setActive((cur) => {
      cur?.resolve(v);
      return null;
    });
  }, []);

  const node = active ? <ThemedPromptView spec={active.spec} onSettle={settle} /> : null;

  return { node, ask };
}

function ThemedPromptView({ spec, onSettle }: { spec: PromptSpec; onSettle: (v: string | boolean | null) => void }) {
  const [value, setValue] = useState(spec.defaultValue ?? '');

  const submit = () => {
    if (spec.input) onSettle(value);
    else onSettle(true); // confirm + info both settle true
  };
  const cancel = () => onSettle(spec.confirm ? false : spec.input ? null : true);

  // b111: deterministic keyboard lift (KAV "padding" mode proved unreliable
  // on device) — the backdrop shrinks by the real keyboard height, so the
  // centered card (and its input) always sit above the keys.
  const kbH = useKbPadding();

  return (
    <View style={[styles.backdrop, kbH > 0 && { paddingBottom: kbH }]}>
      <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={cancel} />
      <View style={styles.card}>
        <Text style={styles.title}>{spec.title}</Text>
        {spec.message ? <Text style={styles.message}>{spec.message}</Text> : null}

        {spec.input ? (
          <TextInput
            style={styles.input}
            value={value}
            onChangeText={setValue}
            placeholder={spec.placeholder}
            placeholderTextColor="#31424d"
            secureTextEntry={spec.input === 'secure'}
            keyboardType={spec.numeric ? 'numeric' : 'default'}
            autoCapitalize="none"
            autoCorrect={false}
            maxLength={spec.maxLength}
            autoFocus
            underlineColorAndroid="transparent"
          />
        ) : null}

        {spec.confirm ? (
          <View>
            <TouchableOpacity style={[styles.btn, spec.danger && styles.btnDanger]} onPress={submit}>
              <Text style={[styles.btnText, spec.danger && styles.btnTextDanger]}>Confirm</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.btnGhost} onPress={cancel}>
              <Text style={styles.btnGhostText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        ) : spec.info ? (
          <TouchableOpacity style={styles.btn} onPress={submit}>
            <Text style={styles.btnText}>OK</Text>
          </TouchableOpacity>
        ) : (
          <View>
            <TouchableOpacity style={styles.btn} onPress={submit}>
              <Text style={styles.btnText}>{spec.submitLabel || 'OK'}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.btnGhost} onPress={cancel}>
              <Text style={styles.btnGhostText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  backdrop: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(4,8,12,0.86)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 22,
    zIndex: 90,
  },
  card: {
    width: '100%', maxWidth: 420,
    backgroundColor: '#101920',
    borderRadius: 14,
    borderWidth: 1,
    borderColor: '#22323d',
    padding: 18,
  },
  title: { color: '#e8f4ef', fontSize: 15, fontWeight: '800', marginBottom: 6 },
  message: { color: '#d69a5c', fontSize: 12, lineHeight: 17, marginBottom: 10 },
  input: {
    backgroundColor: '#0b1218',
    borderWidth: 1,
    borderColor: '#2a3d49',
    borderRadius: 10,
    color: '#e8f4ef',
    fontSize: 15,
    paddingHorizontal: 12,
    paddingVertical: 10,
    marginBottom: 12,
  },
  btn: {
    backgroundColor: '#12211d',
    borderWidth: 1,
    borderColor: '#1f4a42',
    borderRadius: 10,
    paddingVertical: 11,
    alignItems: 'center',
    marginBottom: 8,
  },
  btnDanger: { backgroundColor: '#241213', borderColor: '#5c2a24' },
  btnText: { color: '#7cf4c8', fontSize: 14, fontWeight: '700' },
  btnTextDanger: { color: '#e06c5c' },
  btnGhost: {
    borderWidth: 1,
    borderColor: '#22323d',
    borderRadius: 10,
    paddingVertical: 10,
    alignItems: 'center',
  },
  btnGhostText: { color: '#8fa3ad', fontSize: 13, fontWeight: '600' },
});
