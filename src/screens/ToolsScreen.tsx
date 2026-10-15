/**
 * Tools tab — Vaults, Notes, Stego (web parity, Sept 19 2026).
 *
 * Vault flow = web: create 24 MB deniable container -> UploadPrivateFile ->
 * VeilVault record; unlock via vaultFileSignedUrl({file_uri}) -> fetch ->
 * decoy passphrase opens the outer volume, hidden passphrase the hidden one.
 * Notes = VeilNote entity rows, payload_ciphertext/payload_iv only.
 * Stego = PNG LSB embed/extract, optional passphrase encryption.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  View, Text, TouchableOpacity, TextInput, ScrollView, StyleSheet,
  Alert, ActivityIndicator, Image, Dimensions, Platform,
} from 'react-native';
import * as ImagePicker from 'expo-image-picker';
import * as FileSystem from 'expo-file-system';
import * as MediaLibrary from 'expo-media-library';
import { useThemedPrompt } from './ThemedPrompt';
import { useThemedChooser } from './ThemedSheets';
// expo-document-picker / expo-image-manipulator / expo-sharing are NEW native
// modules (b36) not yet compiled into the installed dev-client binary. A
// static import crashes the whole JS bundle at boot (requireNativeModule
// throws at module-init time), taking down messaging + Notes with it. Load
// them lazily, only when a Vault/Stego action actually needs one, and turn
// the "native module missing" throw into a friendly in-app message instead
// of a fatal error. Once the EAS dev-client (or production) rebuild lands
// with these three deps compiled in, this becomes a normal working import —
// no code change needed, the lazy require just succeeds.
function nativeModuleMissingError(mod: string): Error {
  return new Error(
    `This needs the next app update (native module for "${mod}" isn't installed on this device build yet). ` +
    `Everything else — messaging, Notes, Contacts — is unaffected.`,
  );
}
import type { VeilApp } from '../veil-app';
import { visibleUnderIdentity } from '../owner-veil-filter';
import {
  type VaultFileEntry, createVaultContainer, openVaultContainer, vaultRecord,
  type NotePayload,
  decodePng, encodePng, buildStegoStream, lsbEmbed, extractStego,
  runSelfTest, type SelfTestResult,
} from '../../vendor/device/src/index';
import { fromB64, utf8, toB64, randomBytes } from '../../vendor/crypto-core/src/index';
import { deriveVaultKey, vaultEncrypt, vaultDecrypt, LOCK_CODE_PBKDF2_ITERATIONS } from '../../vendor/crypto-core/src/vault';
import { noteVaultRetrieved } from '../../vendor/device/src/funnel';


type Tool = 'vaults' | 'notes' | 'stego';

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
  if (s.includes('too small to hold'))
    return 'This image is too small to hide that message — pick a larger photo or shorten the message.';
  if (s.includes('rate limit'))
    // b175 (owner Metro repro, Oct 2: burst send surfaced a raw-feeling
    // "Something went wrong" during a transient relay throttle): the relay's
    // anti-abuse limiter is a few-second self-healing cooldown, not a real
    // failure — say so plainly instead of falling through to the scary
    // generic bucket. The composer keeps the drafted text either way.
    return 'The server is briefly busy — wait a few seconds and try again.';
  return 'Something went wrong — please try again.';
}


interface VaultRow { id: string; name: string; byte_length?: number; kdf?: string; cipher?: string; container_uri?: string; owner_veil_id?: string }

/** (b64) Vault containers are ~24 MB and the unlock path re-downloaded the
 *  whole ciphertext from the relay EVERY unlock — 10-30+ s on mobile data.
 *  The container is encrypted end-to-end, so a local file cache is safe:
 *  first unlock downloads + caches, every later unlock is local-only.
 *  Base64 strings over the RN bridge are chunked (large single bridge
 *  calls are the classic "Maximum call stack" trap). */
function vaultCachePath(containerUri: string): string {
  let h = 5381;
  for (let i = 0; i < containerUri.length; i++) h = ((h * 33) ^ containerUri.charCodeAt(i)) >>> 0;
  return `${FileSystem.cacheDirectory}veil-vault-${h.toString(16)}.bin`;
}
async function cacheRead(path: string, expectBytes?: number): Promise<Uint8Array | null> {
  try {
    const info = await FileSystem.getInfoAsync(path);
    if (!info.exists || typeof info.size !== 'number') return null;
    // (b66) a recorded-at-download size wins: if the entity's byte_length field
    // disagrees with the file we ourselves downloaded (field rounding / a
    // different unit), that must NOT bust the cache and force a full
    // re-download on every unlock.
    let metaSize = expectBytes;
    try {
      const meta = await FileSystem.getInfoAsync(`${path}.meta`);
      if (meta.exists) {
        const raw = await FileSystem.readAsStringAsync(`${path}.meta`);
        const n = Number(raw.trim());
        if (Number.isFinite(n) && n > 0) metaSize = n;
      }
    } catch { /* meta is an optimization only */ }
    if (metaSize && info.size !== metaSize) return null; // stale/partial cache
    const chunks: string[] = [];
    for (let off = 0; off < info.size; off += 3 * 1024 * 1024) {
      chunks.push(await FileSystem.readAsStringAsync(path, { encoding: FileSystem.EncodingType.Base64, position: off, length: Math.min(3 * 1024 * 1024, info.size - off) }));
    }
    return fromB64(chunks.join(''));
  } catch { return null; }
}

interface NoteRow { id: string; payload_ciphertext?: string; payload_iv?: string; updated_date?: string; owner_veil_id?: string }

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}
async function readFileBytes(uri: string): Promise<Uint8Array> {
  const b64 = await FileSystem.readAsStringAsync(uri, { encoding: FileSystem.EncodingType.Base64 });
  return b64ToBytes(b64);
}
async function shareBytes(bytes: Uint8Array, filename: string, mime: string): Promise<void> {
  let Sharing: typeof import('expo-sharing');
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    Sharing = require('expo-sharing');
  } catch {
    throw nativeModuleMissingError('expo-sharing');
  }
  const path = `${FileSystem.cacheDirectory}${filename}`;
  await FileSystem.writeAsStringAsync(path, bytesToB64(bytes), { encoding: FileSystem.EncodingType.Base64 });
  await Sharing.shareAsync(path, { mimeType: mime, dialogTitle: filename });
}

/** something the in-app viewer can show (vault file, stego output image, …) */
export interface ViewerItem { name: string; mime: string; bytes: Uint8Array; note?: string }

const PREVIEW_MAX_BYTES = 12 * 1024 * 1024; // keep data-URI image rendering sane

/**
 * In-screen viewer overlay (same proven pattern as ChatScreen's preview —
 * plain absolute overlay, NOT an RN Modal, so it never collides with native
 * pickers/sheets). Images render inline from a data URI; other types offer
 * save/share only. Backdrop tap closes.
 */
/**
 * (b57) FULL-SCREEN viewer — the old card-centred overlay read as a small
 * box pinned to one side of the screen. The owner asked that viewing an
 * unlocked vault file or a stego result take up the whole screen.
 */
function ViewerOverlay({ item, onClose }: { item: ViewerItem; onClose: () => void }) {
  const isImage = item.mime.startsWith('image/');
  const renderable = isImage && item.bytes.length <= PREVIEW_MAX_BYTES;
  return (
    <View style={styles.viewerBackdrop}>
      <TouchableOpacity style={StyleSheet.absoluteFill} onPress={onClose} activeOpacity={1} />
      <View style={styles.viewerFull}>
        <View style={styles.viewerTopBar}>
          <View style={{ flex: 1, paddingRight: 8 }}>
            <Text style={styles.viewerName} numberOfLines={1}>{item.name}</Text>
            <Text style={styles.viewerMeta}>{Math.max(1, Math.ceil(item.bytes.length / 1024))} KB · {item.mime}</Text>
          </View>
          <TouchableOpacity style={styles.viewerCloseBtn} onPress={onClose} hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}>
            <Text style={styles.viewerCloseTxt}>✕</Text>
          </TouchableOpacity>
        </View>
        <View style={styles.viewerBody}>
          {renderable ? (
            <Image
              source={{ uri: `data:${item.mime};base64,${bytesToB64(item.bytes)}` }}
              style={styles.viewerImg}
              resizeMode="contain"
            />
          ) : (
            <Text style={styles.viewerNoPreview}>
              {isImage ? 'This image is too large to preview here — save or share it instead.' : 'Inline preview is not available for this file type — save or share it instead.'}
            </Text>
          )}
        </View>
        {item.note ? <Text style={styles.viewerNote}>{item.note}</Text> : null}
        <View style={styles.viewerFooter}>
          <TouchableOpacity
            style={styles.viewerSaveBtn}
            onPress={() => shareBytes(item.bytes, item.name, item.mime).catch((e) => Alert.alert('Save failed', String((e as Error).message || e)))}
          >
            <Text style={styles.viewerSaveTxt}>Save / Share</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.viewerCloseGhost} onPress={onClose}>
            <Text style={styles.viewerCloseGhostTxt}>Close</Text>
          </TouchableOpacity>
        </View>
      </View>
    </View>
  );
}

/**
 * (b57) Themed "unlocked vault contents" sheet — replaces the system
 * Alert.alert with buttons the owner flagged as off-theme.
 */
function ContentsOverlay({ partition, files, onClose, onShowFile, onSave }: {
  partition: 'outer' | 'hidden';
  files: VaultFileEntry[];
  onClose: () => void;
  onShowFile: (f: VaultFileEntry) => void;
  onSave: (f: VaultFileEntry) => void;
}) {
  return (
    <View style={[styles.viewerBackdrop, styles.backdropCenter]}>
      <TouchableOpacity style={StyleSheet.absoluteFill} onPress={onClose} activeOpacity={1} />
      <View style={styles.contentsCard}>
        <Text style={styles.contentsTitle}>Opened the {partition === 'hidden' ? 'hidden' : 'decoy'} volume</Text>
        <Text style={styles.contentsSub}>{files.length} file{files.length === 1 ? '' : 's'} inside · nothing about the other volume is revealed</Text>
        {files.map((f) => (
          <View key={f.name} style={styles.contentsRow}>
            <View style={{ flex: 1 }}>
              <Text style={styles.rowName} numberOfLines={1}>{f.name}</Text>
              <Text style={styles.rowSub}>{Math.ceil((f.size || 0) / 1024)} KB · {f.type}</Text>
            </View>
            <TouchableOpacity style={styles.btnSm} onPress={() => onShowFile(f)}><Text style={styles.btnSmTxt}>View</Text></TouchableOpacity>
            <TouchableOpacity style={styles.btnSm} onPress={() => onSave(f)}><Text style={styles.btnSmTxt}>Save</Text></TouchableOpacity>
          </View>
        ))}
        <TouchableOpacity style={styles.btnGhost} onPress={onClose}>
          <Text style={styles.btnGhostTxt}>Close</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

export interface ToolScreenProps {
  app: VeilApp;
  /** decoy passcode environment: show plausible empty state, never query the relay */
  decoy?: boolean;
  /** b101: current device's Veil ID — tags new rows and filters extinct-identity ghosts */
  veilId?: string | null;
}

export function VaultsScreen({ app, decoy, veilId }: ToolScreenProps) {
  const [viewer, setViewer] = useState<ViewerItem | null>(null);
  const [contents, setContents] = useState<{ partition: 'outer' | 'hidden'; files: VaultFileEntry[] } | null>(null);
  void decoy;
  const { node: promptNode, ask } = useThemedPrompt();
  // b105: VEIL-branded source chooser for Vault/Stego uploads (owner request
  // Sept 22 — was Alert.alert, a plain white Apple box).
  const { node: chooserNode, choose } = useThemedChooser();
  return (
    <View style={styles.fill}>
      <ScrollView style={styles.fill} contentContainerStyle={styles.body}>
        {decoy ? <Text style={styles.empty}>No vaults yet.</Text> : <VaultsView app={app} veilId={veilId} ask={ask} choose={choose} onShowFile={(f) => setViewer(f)} onContents={setContents} />}
      </ScrollView>
      {contents ? (
        <ContentsOverlay
          partition={contents.partition}
          files={contents.files}
          onClose={() => setContents(null)}
          onShowFile={(f) => { setContents(null); setViewer({ name: f.name, mime: f.type, bytes: fromB64(f.data) }); }}
          onSave={(f) => { void (async () => { try { await shareBytes(fromB64(f.data), f.name, f.type); } catch (e) { Alert.alert('Save failed', String((e as Error).message || e)); } })(); }}
        />
      ) : null}
      {viewer ? <ViewerOverlay item={viewer} onClose={() => setViewer(null)} /> : null}
      {promptNode}
      {chooserNode}
    </View>
  );
}

export function NotesScreen({ app, decoy, veilId }: ToolScreenProps) {
  return (
    <ScrollView style={styles.fill} contentContainerStyle={styles.body}>
      {decoy ? <Text style={styles.empty}>No notes yet.</Text> : <NotesView app={app} veilId={veilId} />}
    </ScrollView>
  );
}

export function StegoScreen({ storage }: Omit<ToolScreenProps, 'app'> & { storage?: VeilApp['storage'] }) {
  const [viewer, setViewer] = useState<ViewerItem | null>(null);
  // b105: VEIL-branded carrier chooser for the Stego flows (owner request Sept 22)
  const { node: chooserNode, choose } = useThemedChooser();
  return (
    <View style={styles.fill}>
      <ScrollView style={styles.fill} contentContainerStyle={styles.body}>
        <StegoView storage={storage} choose={choose} onEmbedded={(item) => setViewer(item)} />
      </ScrollView>
      {viewer ? <ViewerOverlay item={viewer} onClose={() => setViewer(null)} /> : null}
      {chooserNode}
    </View>
  );
}

/* ------------------------------- Vaults -------------------------------- */

function VaultsView({ app, veilId, ask, choose, onShowFile, onContents }: {
  app: VeilApp;
  /** b101: current Veil ID — tags new vault rows, filters extinct-identity ghosts */
  veilId?: string | null;
  ask: ReturnType<typeof useThemedPrompt>['ask'];
  /** b105: VEIL-themed source chooser (see ThemedSheets.tsx) */
  choose: ReturnType<typeof useThemedChooser>['choose'];
  onShowFile: (f: ViewerItem) => void;
  onContents: (c: { partition: 'outer' | 'hidden'; files: VaultFileEntry[] }) => void;
}) {
  const [rows, setRows] = useState<VaultRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [busyNote, setBusyNote] = useState<string | null>(null);
  const [stage, setStage] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('');
  const [pass, setPass] = useState('');
  const [hiddenPass, setHiddenPass] = useState('');
  const [hiddenName, setHiddenName] = useState('');
  const [picked, setPicked] = useState<{ name: string; type: string; uri: string } | null>(null);
  const [hiddenPicked, setHiddenPicked] = useState<{ name: string; type: string; uri: string } | null>(null);

  const refresh = useCallback(async () => {
    setErr(null);
    try {
      const data = (await app.relay.entityList('VeilVault', { sort: '-created_date', limit: 100 })) as { data?: VaultRow[] } | VaultRow[];
      const all = Array.isArray(data) ? data : (data.data ?? []);
      // b101 ghost-row filter — see src/owner-veil-filter.ts
      setRows(visibleUnderIdentity(all, veilId));
    } catch (e) {
      setErr(friendlyError(e, 'tool'));
    }
  }, [app, veilId]);

  useEffect(() => { refresh(); }, [refresh]);

  /**
   * Chooser — photos from the library, or anything from the Files app.
   * b105: VEIL-themed panel (owner request Sept 22) — was Alert.alert, the
   * plain white Apple box. The Photos/Files browsers themselves are iOS
   * system surfaces no app can re-skin; this is the panel the owner sees.
   */
  async function pickFile(forHidden: boolean): Promise<void> {
    const src = await choose({
      title: 'Add a file',
      message: 'Where should VEIL look?',
      options: [
        { label: 'Photos', sub: 'An image or video from your library' },
        { label: 'Files', sub: 'Any file from the Files app' },
      ],
    });
    if (src === 0) void pickFromPhotos(forHidden);
    else if (src === 1) void pickFromDocuments(forHidden);
  }

  async function pickFromPhotos(forHidden: boolean): Promise<void> {
    const r = await ImagePicker.launchImageLibraryAsync({ mediaTypes: ['images'], quality: 1, allowsMultipleSelection: false });
    if (r.canceled) return;
    const a = r.assets?.[0];
    if (!a?.uri) return;
    const name = a.fileName || `photo-${new Date().toISOString().replace(/[:.]/g, '-')}.jpg`;
    const entry = { name, type: a.mimeType || 'image/jpeg', uri: a.uri };
    if (forHidden) setHiddenPicked(entry); else setPicked(entry);
  }

  async function pickFromDocuments(forHidden: boolean): Promise<void> {
    let DocumentPicker: typeof import('expo-document-picker');
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      DocumentPicker = require('expo-document-picker');
    } catch {
      Alert.alert('Not yet on this build', nativeModuleMissingError('expo-document-picker').message);
      return;
    }
    const r = await DocumentPicker.getDocumentAsync({ copyToCacheDirectory: true });
    if (r.canceled) return;
    const f = r.assets?.[0];
    if (!f) return;
    const entry = { name: f.name || 'file.bin', type: f.mimeType || 'application/octet-stream', uri: f.uri };
    if (forHidden) setHiddenPicked(entry); else setPicked(entry);
  }

  async function createVault(): Promise<void> {
    if (!name.trim() || !pass || !picked) {
      Alert.alert('Vault', 'Name, passphrase and a file are required.');
      return;
    }
    setBusy(true); setErr(null);
    try {
      const stageText: Record<string, string> = {
        derive: 'Deriving key (600,000 iterations, one-time cost)',
        encrypt: 'Encrypting volumes',
        container: 'Creating the 24 MB container',
      };
      const fileBytes = await readFileBytes(picked.uri);
      let hiddenBytes: Uint8Array | null = null;
      if (hiddenPicked) hiddenBytes = await readFileBytes(hiddenPicked.uri);
      const { container, byteLength } = await createVaultContainer({
        passphrase: pass,
        file: { name: picked.name, type: picked.type, bytes: fileBytes },
        hiddenPassphrase: hiddenPass || null,
        hiddenFile: hiddenBytes ? { name: hiddenPicked?.name || 'file.bin', type: hiddenPicked?.type || 'application/octet-stream', bytes: hiddenBytes } : null,
        onStage: (s) => setStage(stageText[s] ?? s),
      });
      setStage('Uploading container');
      const uri = await app.relay.uploadPrivateFile({ bytes: container, name: 'container.bin' });
      const rec = vaultRecord(name.trim(), uri, byteLength);
      if (veilId) rec.owner_veil_id = veilId; // b101: own-side identity tag (ghost filter)
      await app.relay.entityCreate('VeilVault', rec);
      setStage(null); setName(''); setPass(''); setHiddenPass(''); setPicked(null); setHiddenPicked(null);
      setShowCreate(false);
      refresh();
    } catch (e) {
      setStage(null);
      setErr(friendlyError(e, 'tool'));
    } finally {
      setBusy(false);
    }
  }

  // (b57) themed passphrase entry — replaces the OS Alert.prompt the owner
  // flagged as an off-theme "normal iPhone box".
  async function unlock(row: VaultRow): Promise<void> {
    if (!row.container_uri) return;
    const pw = (await ask({
      title: 'Unlock vault',
      message: 'Enter the passphrase. Only you can prove which volume you opened — or that any other exists.',
      input: 'secure',
      submitLabel: 'Unlock',
    })) as string | null;
    if (!pw) return;
    setBusy(true); setErr(null); setBusyNote('Opening…');
    try {
      const expect = typeof row.byte_length === 'number' ? row.byte_length : undefined;
      const cPath = vaultCachePath(row.container_uri as string);
      let container = await cacheRead(cPath, expect);
      if (!container) {
        setBusyNote('Fetching the encrypted container…');
        const url = await app.relay.vaultContainerSignedUrl(row.container_uri as string);
        try {
          // native download straight to the cache file — nothing large ever
          // crosses the RN bridge (this expo-file-system has no append
          // option, so a chunked JS write isn't possible; direct download
          // is faster AND bridge-safe)
          await FileSystem.deleteAsync(cPath, { idempotent: true });
          const dl = await FileSystem.downloadAsync(url, cPath);
          if (dl.status !== 200) throw new Error(`container download failed (${dl.status})`);
          try { await FileSystem.writeAsStringAsync(`${cPath}.meta`, String((dl as { size?: number }).size ?? '')); } catch { /* best-effort */ }
          container = await cacheRead(cPath, expect);
          if (!container) throw new Error('cached container unreadable');
        } catch {
          // bridge fallback: fetch via JS and unlock without caching
          container = await app.relay.fetchBytes(url);
        }
      }
      setBusyNote('Deriving keys — this takes a few seconds on this device…');
      const res = await openVaultContainer(container, pw, row.kdf);
      // b139 quality gate: a successful vault open is the activation event for
      // vault users (first retrieval, once per install).
      try { await noteVaultRetrieved(app.relay, app.storage); } catch { /* never a blocker */ }
      // b101 lazy owner-tag: vault containers are PASSPHRASE-derived, so
      // ownership can't be proven at boot like notes (identity-derived key).
      // But a successful unlock means the user can still open this vault —
      // tag it to the current identity so a future identity reset doesn't
      // leave it ghosting in the list with its plaintext name exposed.
      if (veilId && !row.owner_veil_id) {
        app.relay.entityUpdate('VeilVault', row.id, { owner_veil_id: veilId }).catch(() => undefined);
      }
      const files: VaultFileEntry[] = res.manifest.files || [];
      if (!files.length) {
        void ask({ title: `Opened the ${res.partition === 'hidden' ? 'hidden' : 'decoy'} volume`, message: 'This volume is empty.', info: true });
      } else {
        onContents({ partition: res.partition, files });
      }
    } catch (e) {
      setErr(friendlyError(e, 'tool'));
    } finally {
      setBusy(false); setBusyNote(null);
    }
  }

  async function saveVaultFile(f: VaultFileEntry): Promise<void> {
    try {
      await shareBytes(fromB64(f.data), f.name, f.type);
    } catch (e) {
      Alert.alert('Save failed', String((e as Error).message || e));
    }
  }

  async function deleteVault(row: VaultRow): Promise<void> {
    const ok = await ask({
      title: 'Delete vault?',
      message: `"${row.name}" will be removed from your list. The encrypted blob becomes unreferenced (web parity: it is never deleted server-side).`,
      confirm: true,
      danger: true,
    });
    if (!ok) return;
    setBusy(true);
    try { await app.relay.entityDelete('VeilVault', row.id); refresh(); } catch (e) { setErr(friendlyError(e, 'tool')); }
    setBusy(false);
  }

  return (
    <View style={styles.sect}>
      <View style={styles.screenHeadRow}>
        <View style={{ flex: 1 }}>
          <Text style={styles.h1}>Remote encrypted vaults</Text>
          <Text style={styles.p}>Files are encrypted with your passphrase on this device. The server stores ciphertext only.</Text>
        </View>
        <TouchableOpacity style={styles.newBtnSm} onPress={() => setShowCreate((v) => !v)}>
          <Text style={styles.newBtnSmTxt}>{showCreate ? 'Cancel' : '+ New vault'}</Text>
        </TouchableOpacity>
      </View>
      <Text style={styles.warn}>Lose the passphrase, lose the files: there is no recovery.</Text>
      {err ? <Text style={styles.err}>{err}</Text> : null}
      {busy ? (
        <View style={styles.busyRow}><ActivityIndicator color="#7cf4c8" />{stage || busyNote ? <Text style={styles.busyTxt}>{(stage || busyNote)!}…</Text> : null}</View>
      ) : showCreate ? (
        <>
          <Text style={styles.lbl}>Vault name</Text>
          <TextInput style={styles.in} value={name} onChangeText={setName} placeholder="e.g. Travel documents" placeholderTextColor="#31424d" />
          <Text style={styles.lbl}>Decoy passphrase</Text>
          <TextInput style={styles.in} value={pass} onChangeText={setPass} secureTextEntry placeholder="For the volume you can show" placeholderTextColor="#31424d" />
          <TouchableOpacity style={styles.btnGhost} onPress={() => { void pickFile(false); }}>
            <Text style={styles.btnGhostTxt}>{picked ? `Decoy file: ${picked.name}` : 'Add the decoy file — Photos or Files (≤ 8 MB)'}</Text>
          </TouchableOpacity>
          <Text style={[styles.lbl, { marginTop: 12 }]}>Hidden volume (optional)</Text>
          <TextInput style={styles.in} value={hiddenPass} onChangeText={setHiddenPass} secureTextEntry placeholder="Hidden passphrase" placeholderTextColor="#31424d" />
          <TouchableOpacity style={styles.btnGhost} onPress={() => { void pickFile(true); }}>
            <Text style={styles.btnGhostTxt}>{hiddenPicked ? `Hidden file: ${hiddenPicked.name}` : 'Add a file for the hidden volume — Photos or Files'}</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.btn} onPress={createVault}>
            <Text style={styles.btnTxt}>Create vault</Text>
          </TouchableOpacity>
        </>
      ) : null}
      <Text style={[styles.h2, { marginTop: 18 }]}>Your vaults ({rows.length})</Text>
      {rows.map((r) => (
        <View key={r.id} style={styles.row}>
          <View style={{ flex: 1 }}>
            <Text style={styles.rowName}>{r.name}</Text>
            <Text style={styles.rowSub}>{Math.ceil((r.byte_length || 0) / 1048576)} MB · {r.cipher || 'AES-GCM-256'}</Text>
          </View>
          <TouchableOpacity style={styles.btnSm} onPress={() => unlock(r)}><Text style={styles.btnSmTxt}>Unlock</Text></TouchableOpacity>
          <TouchableOpacity style={styles.btnSmGhost} onPress={() => deleteVault(r)}><Text style={styles.btnSmGhostTxt}>Delete</Text></TouchableOpacity>
        </View>
      ))}
      {rows.length === 0 ? <Text style={styles.empty}>No vaults yet.</Text> : null}
    </View>
  );
}

/* -------------------------------- Notes -------------------------------- */

function NotesView({ app, veilId }: { app: VeilApp; veilId?: string | null }) {
  const [rows, setRows] = useState<NoteRow[]>([]);
  const [decrypted, setDecrypted] = useState<Record<string, NotePayload>>({});
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [editing, setEditing] = useState<NoteRow | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const refresh = useCallback(async () => {
    setErr(null);
    try {
      const data = (await app.relay.entityList('VeilNote', { sort: '-updated_date', limit: 100 })) as { data?: NoteRow[] } | NoteRow[];
      const all = Array.isArray(data) ? data : (data.data ?? []);
      // b101 ghost-row filter — see src/owner-veil-filter.ts
      const list = visibleUnderIdentity(all, veilId);
      setRows(list);
      const dec: Record<string, NotePayload> = {};
      for (const r of list) {
        if (r.payload_ciphertext && r.payload_iv) {
          try { dec[r.id] = await app.notes.decryptNote(r.payload_ciphertext, r.payload_iv); } catch { /* key changed or foreign device */ }
        }
      }
      setDecrypted(dec);
    } catch (e) {
      setErr(friendlyError(e, 'tool'));
    }
  }, [app, veilId]);

  useEffect(() => { refresh(); }, [refresh]);

  async function saveNote(): Promise<void> {
    if (!title.trim() && !body.trim()) { Alert.alert('Note', 'Write something first.'); return; }
    setBusy(true); setErr(null);
    try {
      const enc = await app.notes.encryptNote({ title: title.trim() || 'Untitled', body });
      if (editing) await app.relay.entityUpdate('VeilNote', editing.id, {
        payload_ciphertext: enc.ciphertext, payload_iv: enc.iv, byte_length: enc.byteLength,
      });
      else await app.relay.entityCreate('VeilNote', {
        payload_ciphertext: enc.ciphertext, payload_iv: enc.iv, byte_length: enc.byteLength,
        ...(veilId ? { owner_veil_id: veilId } : {}), // b101: own-side identity tag (ghost filter)
      });
      setEditing(null); setTitle(''); setBody(''); setShowCreate(false);
      refresh();
    } catch (e) {
      setErr(friendlyError(e, 'tool'));
    } finally {
      setBusy(false);
    }
  }

  function editNote(r: NoteRow): void {
    const d = decrypted[r.id];
    setEditing(r);
    setTitle(d?.title ?? '');
    setBody(d?.body ?? '');
  }

  async function deleteNote(r: NoteRow): Promise<void> {
    setBusy(true);
    try { await app.relay.entityDelete('VeilNote', r.id); refresh(); } catch (e) { setErr(friendlyError(e, 'tool')); }
    setBusy(false);
  }

  return (
    <View style={styles.sect}>
      <View style={styles.screenHeadRow}>
        <View style={{ flex: 1 }}>
          <Text style={styles.h1}>Encrypted notes</Text>
          <Text style={styles.p}>End-to-end encrypted private notes. Only ciphertext reaches the server; the key never leaves this device.</Text>
        </View>
        <TouchableOpacity style={styles.newBtnSm} onPress={() => { setShowCreate((v) => !v); if (editing) { setEditing(null); setTitle(''); setBody(''); } }}>
          <Text style={styles.newBtnSmTxt}>{showCreate || editing ? 'Cancel' : '+ New note'}</Text>
        </TouchableOpacity>
      </View>
      {err ? <Text style={styles.err}>{err}</Text> : null}
      {(showCreate || editing) ? (
        <>
          <Text style={styles.lbl}>{editing ? 'Edit note' : 'New note'}</Text>
          <TextInput style={styles.in} value={title} onChangeText={setTitle} placeholder="Title" placeholderTextColor="#31424d" />
          <TextInput style={[styles.in, { height: 90 }]} value={body} onChangeText={setBody} multiline placeholder="Write privately…" placeholderTextColor="#31424d" />
          <View style={{ flexDirection: 'row', gap: 10 }}>
            <TouchableOpacity style={styles.btn} onPress={saveNote} disabled={busy}><Text style={styles.btnTxt}>{editing ? 'Save changes' : 'Save note'}</Text></TouchableOpacity>
            <TouchableOpacity style={styles.btnGhost} onPress={() => { setEditing(null); setShowCreate(false); setTitle(''); setBody(''); }}><Text style={styles.btnGhostTxt}>Cancel</Text></TouchableOpacity>
          </View>
        </>
      ) : null}
      <Text style={[styles.h2, { marginTop: 18 }]}>Your notes ({rows.length})</Text>
      {rows.map((r) => {
        const d = decrypted[r.id];
        return (
          <View key={r.id} style={styles.row}>
            <View style={{ flex: 1 }}>
              <Text style={styles.rowName} numberOfLines={1}>{d ? d.title : '(encrypted on this note key)'}</Text>
              <Text style={styles.rowSub} numberOfLines={2}>{d ? d.body : 'Locked to this device\'s key'}</Text>
            </View>
            {/* b101: Edit only when this identity's key can decrypt the row — editing an
                undecryptable ghost would silently overwrite another identity's content. */}
            {d ? (
              <TouchableOpacity style={styles.btnSm} onPress={() => editNote(r)}><Text style={styles.btnSmTxt}>Edit</Text></TouchableOpacity>
            ) : null}
            <TouchableOpacity style={styles.btnSmGhost} onPress={() => deleteNote(r)}><Text style={styles.btnSmGhostTxt}>Delete</Text></TouchableOpacity>
          </View>
        );
      })}
      {rows.length === 0 ? <Text style={styles.empty}>No notes yet.</Text> : null}
    </View>
  );
}

/* -------------------------------- Stego -------------------------------- */

function StegoView({ storage, choose, onEmbedded }: { storage?: VeilApp['storage']; choose: (spec: import('./ThemedSheets').ChooserSpec) => Promise<number | null>; onEmbedded: (item: ViewerItem) => void }) {
  const { node: stegoPromptNode, ask: stegoAsk } = useThemedPrompt();
  const [mode, setMode] = useState<'embed' | 'extract' | 'selftest'>('embed');
  const [message, setMessage] = useState('');
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [selfTestResults, setSelfTestResults] = useState<SelfTestResult[] | null>(null);

  async function pickCarrier(): Promise<{ uri: string; name: string; w?: number; h?: number } | null> {
    const r = await ImagePicker.launchImageLibraryAsync({ mediaTypes: ['images'], quality: 1 });
    if (r.canceled) return null;
    const a = r.assets?.[0];
    if (!a?.uri) return null;
    return { uri: a.uri, name: a.fileName || 'stego.png', w: a.width, h: a.height };
  }

  /** carrier from the Files app (image only — same lazy-require pattern). */
  async function pickCarrierFromFiles(): Promise<{ uri: string; name: string; w?: number; h?: number } | null> {
    let DocumentPicker: typeof import('expo-document-picker');
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      DocumentPicker = require('expo-document-picker');
    } catch {
      throw nativeModuleMissingError('expo-document-picker');
    }
    const r = await DocumentPicker.getDocumentAsync({ type: 'image/*', copyToCacheDirectory: true });
    if (r.canceled) return null;
    const f = (r as { assets?: { uri: string; name?: string }[] }).assets?.[0];
    if (!f?.uri) return null;
    return { uri: f.uri, name: f.name || 'carrier.png' };
  }

  /**
   * b105: VEIL-themed carrier chooser (owner request Sept 22) — Photos or
   * Files, in the app's own dark panel instead of going straight into the
   * system picker with no branded entry point.
   */
  async function pickCarrierThemed(kind: 'embed' | 'extract'): Promise<{ uri: string; name: string; w?: number; h?: number } | null> {
    const src = await choose({
      title: kind === 'embed' ? 'Choose a carrier image' : 'Choose the stego image',
      message: kind === 'embed'
        ? 'The innocent-looking photo your message hides inside.'
        : 'The image that carries a hidden message.',
      options: [
        { label: 'Photos', sub: 'From your photo library' },
        { label: 'Files', sub: 'A lossless PNG from the Files app' },
      ],
    });
    if (src === 0) return pickCarrier();
    if (src === 1) return pickCarrierFromFiles();
    return null;
  }

  async function embed(): Promise<void> {
    setErr(null); setResult(null);
    if (!message.trim()) { setErr('Write the message first.'); return; }
    setBusy(true);
    try {
      const carrier = await pickCarrierThemed('embed');
      if (!carrier) { setBusy(false); return; }
      // normalise the carrier to PNG pixels (JPEG etc. -> RGBA), web canvas parity
      let ImageManipulator: typeof import('expo-image-manipulator');
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        ImageManipulator = require('expo-image-manipulator');
      } catch {
        throw nativeModuleMissingError('expo-image-manipulator');
      }
      // b111 SPEED FIX: a full-res 12MP photo is 48 MB of RGBA that then
      // runs through pure-JS PNG decode + LSB + re-encode under Hermes (no
      // JIT) — tens of seconds. Downscaling the carrier to <=2048px on the
      // native side first cuts that ~36x. Capacity at 2048px is ~1.1 MB of LSB
      // payload, far above the 256 KB message ceiling, and the embedded
      // stream is byte-identical so web extraction is unaffected.
      // b114 (owner report Sept 22: "Unsupported PNG: only 8-bit images
      // are supported" on a live-camera / Files-app carrier): our PNG codec
      // only decodes 8-bit RGB(A) — but manipulateAsync with an EMPTY
      // actions array is a byte pass-through on iOS, so a source image with
      // a higher bit depth (HDR/wide-gamut camera captures; some ProRAW-
      // adjacent pipelines emit 16-bit-per-channel PNG/HEIC) sails through
      // unconverted and our decoder correctly rejects it. Also: the Files
      // picker never reported carrier.w/h, so those carriers silently
      // skipped the b111 downscale entirely. Fix both: always resolve real
      // pixel dimensions first, then ALWAYS run one genuine resize action
      // (to the same size when no downscale is needed) — a real transform
      // forces iOS to fully re-rasterize to standard 8-bit sRGB, which our
      // codec (and the web canvas, for cross-platform extraction) reads.
      let srcW = carrier.w ?? 0;
      let srcH = carrier.h ?? 0;
      if (!srcW || !srcH) {
        try {
          const size = await new Promise<{ w: number; h: number }>((resolve, reject) => {
            Image.getSize(carrier.uri, (w, h) => resolve({ w, h }), reject);
          });
          srcW = size.w; srcH = size.h;
        } catch {
          throw new Error('Could not read this image’s dimensions. Try a different photo.');
        }
      }
      const mw = Math.max(srcW, srcH);
      const scale = mw > 2048 ? 2048 / mw : 1;
      const targetW = Math.max(1, Math.round(srcW * scale));
      const targetH = Math.max(1, Math.round(srcH * scale));
      const norm = await ImageManipulator.manipulateAsync(
        carrier.uri,
        [{ resize: { width: targetW, height: targetH } } as unknown as import('expo-image-manipulator').Action],
        { format: ImageManipulator.SaveFormat.PNG, compress: 1 },
      );
      const pngBytes = await readFileBytes(norm.uri);
      let img: ReturnType<typeof decodePng>;
      try {
        img = decodePng(pngBytes);
      } catch (decErr) {
        // Extremely defensive fallback: if some device/OS combo still hands
        // back a non-8-bit PNG even after a forced resize, re-run through a
        // lossy JPEG bounce (JPEG is always 8-bit) before the final PNG pass
        // rather than failing the embed outright.
        const bounced = await ImageManipulator.manipulateAsync(norm.uri, [], { format: ImageManipulator.SaveFormat.JPEG, compress: 0.98 });
        const rePng = await ImageManipulator.manipulateAsync(bounced.uri, [], { format: ImageManipulator.SaveFormat.PNG, compress: 1 });
        const rePngBytes = await readFileBytes(rePng.uri);
        img = decodePng(rePngBytes);
      }
      lsbEmbed(img.rgba, await buildStegoStream(message, pass.trim() || null));
      const out = encodePng(img);
      // b92 F14 (b91 audit): FULL Photos access, not add-only. iOS write-only
      // permission does NOT allow deleting assets, so stego images saved
      // under it could NOT be removed by the duress wipe — they would
      // survive a duress event against the "nothing survives" claim.
      // Full access keeps the duress purge able to delete veil_saved_media.
      const perm = await MediaLibrary.requestPermissionsAsync(false);
      if (!perm.granted) { setErr('Photos access is required to save (and later purge under a duress wipe) the stego image.'); setBusy(false); return; }
      const path = `${FileSystem.cacheDirectory}veil-stego-${Date.now()}.png`;
      await FileSystem.writeAsStringAsync(path, bytesToB64(out), { encoding: FileSystem.EncodingType.Base64 });
      const saved = (await MediaLibrary.saveToLibraryAsync(path)) as unknown as string | undefined;
      await FileSystem.deleteAsync(path, { idempotent: true });
      // (b64) track the Photos asset id — the duress wipe deletes these so
      // stego images don't outlive the device data they belong to.
      try {
        if (saved && storage) {
          const raw = await storage.get('veil_saved_media');
          const arr = raw ? (JSON.parse(raw) as string[]) : [];
          arr.push(String(saved));
          await storage.set('veil_saved_media', JSON.stringify(arr));
        }
      } catch { /* tracking is best-effort */ }
      setResult('Stego image saved to Photos. Send it like any picture — the words travel inside, invisible. Do not re-upload through apps that recompress.');
      // show the result right here so it can be viewed, not just saved
      onEmbedded({
        name: `stego-${Date.now()}.png`,
        mime: 'image/png',
        bytes: out,
        note: 'Saved to Photos. Looks like the original picture — the message is inside.',
      });
      // AUDIT FIX (Sept 19): the passphrase (and message) stayed in the boxes
      // after a successful embed — a shoulder-surf/screen-lock risk once the
      // image is already saved and the secret has done its job.
      setPass('');
      setMessage('');
    } catch (e) {
      setErr(friendlyError(e, 'tool'));
    } finally {
      setBusy(false);
    }
  }

  async function extract(): Promise<void> {
    setErr(null); setResult(null);
    setBusy(true);
    try {
      const carrier = await pickCarrierThemed('extract');
      if (!carrier) { setBusy(false); return; }
      const pngBytes = await readFileBytes(carrier.uri);
      // (b66) refuse non-PNG up front: a JPEG/HEIC from Photos (or any app
      // that recompressed the image) has destroyed the LSB payload — decode
      // would either fail cryptically or extract garbage.
      if (pngBytes.length < 8 || pngBytes[0] !== 0x89 || pngBytes[1] !== 0x50 || pngBytes[2] !== 0x4e || pngBytes[3] !== 0x47) {
        throw new Error('That file is not a lossless PNG. Photos or another app recompressed it (JPEG/HEIC) and the hidden data cannot survive compression. Pick the original stego PNG.');
      }
      const img = decodePng(pngBytes); // stego output is always PNG (lossless)
      let msg: string;
      try {
        msg = await extractStego(img.rgba, pass.trim() || null);
      } catch {
        // (b66) the raw crypto error is platform-varying gibberish
        // ('invalid ghash tag' / 'operation-specific reason') — the
        // realistic causes are a wrong passphrase or a pixel change; say so
        // in plain words instead of echoing the crypto layer.
        setErr('The hidden data did not decrypt. Most likely the passphrase is different from the one used to hide it (watch for autocorrect and spaces). If the passphrase is right, the image pixels were altered after embedding — re-send the original stego PNG, never a re-compressed copy.');
        return;
      }
      setResult(msg);
    } catch (e) {
      setErr(friendlyError(e, 'tool'));
    } finally {
      setBusy(false);
    }
  }

  /** (b69) owner ask: save the extracted payload ENCRYPTED on device.
   *  AES-256-GCM with a locally-derived key (PBKDF2-SHA256, 210k) — the
   *  plaintext never touches the disk or the share sheet unless asked. */
  async function saveResultEncrypted(): Promise<void> {
    if (!result) return;
    const pw = (await stegoAsk({
      title: 'Save encrypted copy',
      message: 'The extracted payload will be encrypted with this passphrase before it is written to the device. Anyone with the file still needs the passphrase.',
      input: 'secure',
      submitLabel: 'Save encrypted',
    })) as string | null;
    if (!pw) return;
    setBusy(true);
    try {
      const salt = randomBytes(16);
      const iv = randomBytes(12);
      const key = await deriveVaultKey(pw, toB64(salt), LOCK_CODE_PBKDF2_ITERATIONS);
      const ct = await vaultEncrypt(key, iv, utf8(result));
      const blob = utf8(JSON.stringify({ v: 1, salt: toB64(salt), iv: toB64(iv), iters: LOCK_CODE_PBKDF2_ITERATIONS, ct: toB64(ct) }));
      const name = `veil-extract-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.veilenc`;
      const path = `${FileSystem.documentDirectory}${name}`;
      await FileSystem.writeAsStringAsync(path, toB64(blob), { encoding: FileSystem.EncodingType.Base64 });
      Alert.alert('Saved encrypted', `${name}\nAES-256-GCM, encrypted on this device.\nOpen it later from Stego → Extract → Open encrypted file.`);
    } catch (e) {
      Alert.alert('Save failed', String((e as Error).message || e));
    } finally { setBusy(false); }
  }

  /** (b69) open a saved .veilenc back into plaintext (in-memory result only). */
  async function openEncryptedFile(): Promise<void> {
    let DocumentPicker: typeof import('expo-document-picker');
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      DocumentPicker = require('expo-document-picker');
    } catch {
      Alert.alert('Not yet on this build', nativeModuleMissingError('expo-document-picker').message);
      return;
    }
    const r = await DocumentPicker.getDocumentAsync({ copyToCacheDirectory: true });
    if (r.canceled) return;
    const file = (r as { assets?: { uri: string; name: string }[] }).assets?.[0];
    if (!file?.uri) return;
    const pw = (await stegoAsk({
      title: 'Open encrypted file',
      message: `Enter the passphrase for "${file.name}".`,
      input: 'secure',
      submitLabel: 'Open',
    })) as string | null;
    if (!pw) return;
    setBusy(true);
    try {
      const b64 = await FileSystem.readAsStringAsync(file.uri, { encoding: FileSystem.EncodingType.Base64 });
      const rec = JSON.parse(new TextDecoder().decode(fromB64(b64))) as { salt: string; iv: string; iters: number; ct: string };
      const key = await deriveVaultKey(pw, rec.salt, rec.iters);
      const pt = await vaultDecrypt(key, fromB64(rec.iv), fromB64(rec.ct));
      setResult(new TextDecoder().decode(pt));
      setMode('extract');
    } catch {
      setErr('The file did not decrypt — wrong passphrase, or the file was not a VEIL encrypted extract.');
    } finally { setBusy(false); }
  }

  async function runDeviceSelfTest(): Promise<void> {
    setErr(null); setSelfTestResults(null);
    setBusy(true);
    try {
      const results = await runSelfTest();
      setSelfTestResults(results);
    } catch (e) {
      setErr(friendlyError(e, 'tool'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <View style={styles.sect}>
      <Text style={styles.h1}>Steganography</Text>
      <Text style={styles.p}>Hide a message inside an ordinary picture. With a passphrase it is also encrypted; without one it is still not visible to the eye. Honest limit: this hides the message from a casual viewer — resistance to steganalysis tools is not claimed. Only lossless PNG survives.</Text>
      {err ? <Text style={styles.err}>{err}</Text> : null}
      <View style={{ flexDirection: 'row', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
        <TouchableOpacity style={[styles.btnSm, mode === 'embed' && styles.btnSmOn]} onPress={() => setMode('embed')}><Text style={[styles.btnSmTxt, mode === 'embed' && styles.btnSmTxtOn]}>Hide a message</Text></TouchableOpacity>
        <TouchableOpacity style={[styles.btnSmGhost, mode === 'extract' && styles.btnSmGhostOn]} onPress={() => setMode('extract')}><Text style={styles.btnSmGhostTxt}>Extract</Text></TouchableOpacity>
        <TouchableOpacity style={[styles.btnSmGhost, mode === 'selftest' && styles.btnSmGhostOn]} onPress={() => setMode('selftest')}><Text style={styles.btnSmGhostTxt}>Crypto self-test</Text></TouchableOpacity>
      </View>
      {mode === 'embed' ? (
        <>
          <TextInput style={[styles.in, { height: 90 }]} value={message} onChangeText={setMessage} multiline placeholder="The words to hide (≤ 256 KB)" placeholderTextColor="#31424d" />
          <TextInput style={styles.in} value={pass} onChangeText={setPass} secureTextEntry placeholder="Optional passphrase (adds encryption)" placeholderTextColor="#31424d" />
          <TouchableOpacity style={styles.btn} onPress={embed} disabled={busy}><Text style={styles.btnTxt}>{busy ? 'Working…' : 'Choose image & hide'}</Text></TouchableOpacity>
        </>
      ) : mode === 'extract' ? (
        <>
          <TextInput style={styles.in} value={pass} onChangeText={setPass} secureTextEntry placeholder="Passphrase (if it was encrypted)" placeholderTextColor="#31424d" />
          <TouchableOpacity style={styles.btn} onPress={extract} disabled={busy}><Text style={styles.btnTxt}>{busy ? 'Reading…' : 'Choose image & extract'}</Text></TouchableOpacity>
          <TouchableOpacity style={styles.btnGhost2} onPress={openEncryptedFile} disabled={busy}><Text style={styles.btnGhost2Txt}>Open encrypted file</Text></TouchableOpacity>
        </>
      ) : (
        <>
          <Text style={styles.lbl}>Crypto self-test</Text>
          <Text style={styles.p}>Runs the protocol's parity suite against this device's encryption core — a real roundtrip of every primitive VEIL depends on, on this exact build.</Text>
          <TouchableOpacity style={styles.btn} onPress={runDeviceSelfTest} disabled={busy}><Text style={styles.btnTxt}>{busy ? 'Running…' : 'Run the self-test'}</Text></TouchableOpacity>
          {selfTestResults ? (
            <View style={styles.selfTestBox}>
              {selfTestResults.map((r) => (
                <View key={r.name} style={styles.selfTestRow}>
                  <Text style={r.ok ? styles.selfTestOk : styles.selfTestFail}>{r.ok ? 'PASS' : 'FAIL'}</Text>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.selfTestName}>{r.name}</Text>
                    <Text style={styles.selfTestDetail}>{r.detail}</Text>
                  </View>
                  <Text style={styles.selfTestMs}>{r.ms} ms</Text>
                </View>
              ))}
            </View>
          ) : null}
        </>
      )}
      {result ? (
        <View style={styles.resultBox}>
          <Text style={styles.resultTxt}>{result}</Text>
          <TouchableOpacity style={styles.btnGhost2} onPress={saveResultEncrypted} disabled={busy}>
            <Text style={styles.btnGhost2Txt}>Save encrypted to device</Text>
          </TouchableOpacity>
        </View>
      ) : null}
      {stegoPromptNode}
    </View>
  );
}

const styles = StyleSheet.create({
  screenHeadRow: { flexDirection: 'row', alignItems: 'flex-start', gap: 10, marginBottom: 6 },
  newBtnSm: { borderWidth: 1, borderColor: '#7cf4c8', borderRadius: 8, paddingHorizontal: 12, paddingVertical: 7 },
  newBtnSmTxt: { color: '#7cf4c8', fontSize: 12, fontWeight: '700' },
  warn: { color: '#8a6d3b', fontSize: 12, marginBottom: 10, fontStyle: 'italic' },
  selfTestBox: { marginTop: 12, borderWidth: 1, borderColor: '#1c2731', borderRadius: 10, padding: 4, backgroundColor: '#0e1620' },
  selfTestRow: { flexDirection: 'row', alignItems: 'flex-start', gap: 8, padding: 8, borderBottomWidth: 1, borderBottomColor: '#141d25' },
  selfTestOk: { color: '#7cf4c8', fontSize: 11, fontWeight: '800', marginTop: 2, width: 34 },
  selfTestFail: { color: '#e8836f', fontSize: 11, fontWeight: '800', marginTop: 2, width: 34 },
  selfTestName: { color: '#d5e3dd', fontSize: 13, fontWeight: '700' },
  selfTestDetail: { color: '#5a6b76', fontSize: 11, lineHeight: 15, marginTop: 2 },
  selfTestMs: { color: '#5a6b76', fontSize: 11, marginTop: 2 },
  fill: { flex: 1, backgroundColor: '#0b0f14' },
  tabBar: { flexDirection: 'row', paddingHorizontal: 12, borderBottomWidth: 1, borderBottomColor: '#141d25' },
  tab: { paddingVertical: 10, paddingHorizontal: 14, marginRight: 4 },
  tabOn: { borderBottomWidth: 2, borderBottomColor: '#7cf4c8' },
  tabText: { color: '#41505b', fontSize: 13, fontWeight: '600' },
  tabTextOn: { color: '#7cf4c8' },
  body: { padding: 16, paddingBottom: 48 },
  sect: {},
  h1: { color: '#e8f2ee', fontSize: 17, fontWeight: '800', marginBottom: 6 },
  h2: { color: '#8aa0ad', fontSize: 13, fontWeight: '700', marginBottom: 8 },
  p: { color: '#7a8b96', fontSize: 12, lineHeight: 17, marginBottom: 14 },
  lbl: { color: '#8aa0ad', fontSize: 12, marginBottom: 4 },
  in: { backgroundColor: '#101821', borderWidth: 1, borderColor: '#1c2833', borderRadius: 8, color: '#d5e3dd', paddingHorizontal: 12, paddingVertical: 10, marginBottom: 10, fontSize: 14 },
  btn: { backgroundColor: '#7cf4c8', borderRadius: 8, paddingHorizontal: 16, paddingVertical: 12, alignSelf: 'flex-start', marginBottom: 6 },
  btnTxt: { color: '#06231c', fontWeight: '800', fontSize: 13 },
  // (b57) viewerBackdrop is now FULL-SCREEN: the card fills the viewport so
  // unlocked-vault / stego content takes the whole screen (owner request).
  // (b67) explicit top/left/right/bottom instead of the 'inset' shorthand —
  // inset support is inconsistent enough on RN 0.76 that the backdrop could
  // collapse to zero size, leaving the card unpositioned and the background
  // undimmed (owner screenshot: vault list visible through an uncentered modal).
  viewerBackdrop: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(3,7,11,0.97)', zIndex: 50 },
  viewerFull: { flex: 1, width: '100%', padding: 16 },
  viewerTopBar: { flexDirection: 'row', alignItems: 'center', paddingTop: Platform.OS === 'ios' ? 44 : 20, paddingBottom: 10 },
  viewerCloseBtn: { width: 34, height: 34, borderRadius: 17, backgroundColor: '#101920', borderWidth: 1, borderColor: '#22323d', alignItems: 'center', justifyContent: 'center' },
  viewerCloseTxt: { color: '#8fa3ad', fontSize: 15, fontWeight: '800' },
  viewerBody: { flex: 1, justifyContent: 'center' },
  viewerName: { color: '#e8f4ef', fontSize: 15, fontWeight: '800' },
  viewerMeta: { color: '#5a6b76', fontSize: 12, marginTop: 2 },
  viewerImg: { width: '100%', height: '100%', backgroundColor: '#0b0f14' },
  viewerNoPreview: { color: '#8fa3ad', fontSize: 13, lineHeight: 19, textAlign: 'center' },
  viewerNote: { color: '#7cf4c8', fontSize: 12, marginBottom: 8, textAlign: 'center' },
  viewerFooter: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingBottom: 30, paddingTop: 10 },
  viewerSaveBtn: { flex: 1, backgroundColor: '#12211d', borderWidth: 1, borderColor: '#1f4a42', borderRadius: 10, paddingVertical: 12, alignItems: 'center' },
  viewerSaveTxt: { color: '#7cf4c8', fontSize: 14, fontWeight: '700' },
  viewerCloseGhost: { borderWidth: 1, borderColor: '#22323d', borderRadius: 10, paddingVertical: 12, paddingHorizontal: 20, alignItems: 'center' },
  viewerCloseGhostTxt: { color: '#8fa3ad', fontSize: 14, fontWeight: '600' },
  // (b66) owner: the unlocked-vault sheet read as a stray small box — now a
  // deliberate centered sheet, 92% wide
  backdropCenter: { justifyContent: 'center', alignItems: 'center' },
  contentsCard: { backgroundColor: '#101920', borderRadius: 14, borderWidth: 1, borderColor: '#22323d', padding: 18, width: '92%', maxHeight: '82%' },
  contentsTitle: { color: '#e8f4ef', fontSize: 15, fontWeight: '800', marginBottom: 4 },
  contentsSub: { color: '#8fa3ad', fontSize: 12, marginBottom: 12 },
  contentsRow: { flexDirection: 'row', alignItems: 'center', gap: 8, backgroundColor: '#0b1218', borderWidth: 1, borderColor: '#1c2833', borderRadius: 10, padding: 12, marginBottom: 8 },
  btnGhost: { borderWidth: 1, borderColor: '#2a3b46', borderRadius: 8, paddingHorizontal: 16, paddingVertical: 12, alignSelf: 'flex-start', marginBottom: 6 },
  btnGhost2: { borderWidth: 1, borderColor: '#2a3b46', borderRadius: 8, paddingHorizontal: 16, paddingVertical: 12, alignSelf: 'flex-start', marginTop: 10 },
  btnGhost2Txt: { color: '#7cf4c8', fontSize: 13, fontWeight: '600' },
  btnGhostTxt: { color: '#7a8b96', fontSize: 13, fontWeight: '600' },
  row: { flexDirection: 'row', alignItems: 'center', gap: 8, backgroundColor: '#101821', borderRadius: 10, padding: 12, marginBottom: 8, borderWidth: 1, borderColor: '#141d25' },
  rowName: { color: '#d5e3dd', fontSize: 14, fontWeight: '700' },
  rowSub: { color: '#5a6b76', fontSize: 11, marginTop: 2 },
  btnSm: { backgroundColor: '#1b2a24', borderRadius: 6, paddingHorizontal: 10, paddingVertical: 8 },
  btnSmOn: { backgroundColor: '#7cf4c8' },
  btnSmTxt: { color: '#7cf4c8', fontSize: 12, fontWeight: '700' },
  btnSmTxtOn: { color: '#06231c' }, // VEIL-P1 Sept 19: teal text was invisible on the teal 'on' background
  btnSmGhost: { borderWidth: 1, borderColor: '#2a3b46', borderRadius: 6, paddingHorizontal: 10, paddingVertical: 8 },
  btnSmGhostOn: { borderColor: '#7cf4c8' },
  btnSmGhostTxt: { color: '#7a8b96', fontSize: 12 },
  err: { color: '#ff9d9d', fontSize: 12, marginBottom: 10 },
  empty: { color: '#41505b', fontSize: 12, fontStyle: 'italic' },
  busyRow: { flexDirection: 'row', alignItems: 'center', gap: 8, marginVertical: 12 },
  busyTxt: { color: '#7a8b96', fontSize: 12 },
  resultBox: { backgroundColor: '#101821', borderWidth: 1, borderColor: '#1c2833', borderRadius: 10, padding: 12, marginTop: 12 },
  resultTxt: { color: '#d5e3dd', fontSize: 13, lineHeight: 19 },
});
