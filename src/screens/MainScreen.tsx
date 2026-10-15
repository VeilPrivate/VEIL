import React from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Image } from 'react-native';
import { useThemedShare } from './ThemedSheets';
import { Ionicons } from '@expo/vector-icons';
import { SessionsScreen, type SessionRow } from './SessionsScreen';
import { ContactsScreen, type ContactRow, type LookupResult } from './ContactsScreen';
import { SettingsScreen } from './SettingsScreen';
import { VaultsScreen, NotesScreen, StegoScreen } from './ToolsScreen';
import type { VeilApp } from '../veil-app';
import { type VeilSettings } from '../../vendor/device/src/settings';

export interface MainScreenProps {
  decoyMode: boolean;
  veilId: string | null;
  email?: string | null;
  busy: boolean;
  onSignOut: () => void;
  sessions: SessionRow[];
  onRefreshSessions: () => void;
  onOpenSession: (token: string) => void;
  onNewSession: () => void;
  onCreateInvite: () => Promise<string>;
  onJoinInvite: (link: string) => Promise<void>;
  contacts: ContactRow[];
  contactsError: string | null;
  onLookup: (veilId: string) => Promise<LookupResult | null>;
  onPin: (lookup: LookupResult) => Promise<void>;
  /** b57: unpin a contact (device-local pin removal, two-tap confirm in the UI) */
  onUnpin: (veilId: string) => Promise<void>;
  onMessage: (veilId: string) => void;
  onVerify: (veilId: string) => Promise<void>;
  onSetNickname: (veilId: string, nickname: string) => void;
  /** b62 groups: create a group + invite links (creator flow) */
  onCreateGroup: (name: string, inviteCount: number) => Promise<{ groupName: string; inviteLinks: string[] }>;
  settings: VeilSettings;
  onSettingsChange: (s: VeilSettings) => void;
  onRunCheckup: () => void;
  appLockEnabled: boolean;
  onSetAppLock: (pass: string, decoy?: string | null, duress?: string | null) => Promise<void>;
  onRemoveAppLock: (pass: string) => Promise<boolean>;
  onLockNow: () => void;
  onWipeDevice: () => Promise<void>;
  onDeleteAccount: () => Promise<void>;
  onViewIntro: () => void;
  webBaseUrl: string;
  onCreateTransfer: () => Promise<{ link: string; sessionCount: number; groupCount: number; hasIdentity: boolean }>;
  onReceiveTransfer: (link: string) => Promise<{ sessionCount: number; importedCount: number; skippedExisting: number; identityImported: boolean; identityKept: boolean }>;
  onVerifyPhrase: (phrase: string) => Promise<boolean>;
  onRemoveIdentity: () => Promise<void>;
  onGenerateNewVeilId: () => Promise<void>;
  onCreateIdentity: () => void;
  /** dismissible in-app "Secure your VEIL" prompt (checkup + app lock) */
  securePrompt: boolean;
  onDismissSecurePrompt: () => void;
  /** b139 funnel fix: the local "Getting started" welcome thread row */
  welcomeVisible: boolean;
  onOpenWelcome: () => void;
  /** b196-r5: Founding Tester Forum banner (non-members only) */
  forumBannerVisible?: boolean;
  forumBannerBusy?: boolean;
  onJoinForum?: () => void;
  onDismissForumBanner?: () => void;
  tab: 'sessions' | 'contacts' | 'vaults' | 'stego' | 'notes' | 'settings';
  onTab: (tab: 'sessions' | 'contacts' | 'vaults' | 'stego' | 'notes' | 'settings') => void;
  app: VeilApp;
}

/**
 * Signed-in shell (Phase B step 4): identity strip + Conversations/Contacts tabs.
 * The chat pane mounts on session open (next step).
 */
export function MainScreen({
  app, decoyMode, veilId, email, busy, onSignOut,
  sessions, onRefreshSessions, onOpenSession, onNewSession, onCreateInvite, onJoinInvite,
  contacts, contactsError, onLookup, onPin, onUnpin, onMessage, onVerify, onSetNickname, onCreateGroup, settings, onSettingsChange, onRunCheckup, tab, onTab,
  appLockEnabled, onSetAppLock, onRemoveAppLock,
  onLockNow, onWipeDevice, onDeleteAccount, onViewIntro, webBaseUrl,
  onCreateTransfer, onReceiveTransfer, onVerifyPhrase, onRemoveIdentity, onGenerateNewVeilId, onCreateIdentity,
  securePrompt, onDismissSecurePrompt, welcomeVisible, onOpenWelcome,
  forumBannerVisible, forumBannerBusy, onJoinForum, onDismissForumBanner,
}: MainScreenProps) {
  // b198 (owner direction, battery): NOTES ARE GATED — entering the Notes tab
  // demands the app-lock passcode, every time. The whole-app lock covers the
  // shell; this gate covers the one screen that holds long-lived private
  // text. Re-locks on every tab entry; the app-lock record is the only key.
  const [notesUnlocked, setNotesUnlocked] = React.useState(false);
  const [notesCode, setNotesCode] = React.useState('');
  const [notesErr, setNotesErr] = React.useState<string | null>(null);
  const [notesBusy, setNotesBusy] = React.useState(false);
  React.useEffect(() => { if (tab === 'notes') { setNotesUnlocked(false); setNotesCode(''); setNotesErr(null); } }, [tab]);
  const unlockNotes = async () => {
    if (notesBusy || !notesCode) return;
    setNotesBusy(true);
    try {
      const kind = await app.appLock.verify(notesCode);
      if (kind === 'real') { setNotesUnlocked(true); setNotesErr(null); setNotesCode(''); }
      else { setNotesErr('Wrong passcode.'); setNotesCode(''); }
    } catch { setNotesErr('Could not verify — try again.'); }
    finally { setNotesBusy(false); }
  };
  // b105: VEIL-branded share card for the Veil ID (owner request Sept 22 —
  // the identity strip jumped straight into Apple's stock share sheet)
  const { node: shareNode, share: openShare } = useThemedShare();
  const tabIcon = (name: keyof typeof Ionicons.glyphMap, active: boolean) => (
    <Ionicons name={name} size={21} color={active ? '#7cf4c8' : '#4a5b66'} />
  );
  // b90: total unread across threads — highlights the Chat tab icon
  const unreadTotal = sessions.reduce((n, r) => n + (r.unread || 0), 0);

  return (
    <View style={styles.fill}>
      {shareNode}
      <View style={styles.header}>
        <View style={styles.brandRow}>
          <Image source={require('../../assets/logo.png')} style={styles.logoSmall} />
          <Text style={styles.logo}>VEIL</Text>
        </View>
        <TouchableOpacity onPress={onSignOut} disabled={busy}>
          <Text style={styles.signOut}>{busy ? '…' : 'Sign out'}</Text>
        </TouchableOpacity>
      </View>

      <TouchableOpacity
        style={styles.identityStrip}
        disabled={!veilId}
        activeOpacity={0.6}
        onPress={() => { if (veilId) openShare({ value: veilId, kicker: 'Keys sealed in the device keychain — people use it to look you up.' }); }}
      >
        <View style={styles.veilIdRow}>
          {veilId ? <View style={styles.idDot} /> : null}
          <Text style={styles.veilId} numberOfLines={1}>{veilId ?? 'no identity on this device'}</Text>
        </View>
        {veilId ? <Text style={styles.ok}>Keys sealed in the device keychain · tap to share your Veil ID</Text> : null}
      </TouchableOpacity>

      {securePrompt ? (
        <View style={styles.secureBox}>
          <Text style={styles.secureTitle}>Secure your VEIL</Text>
          <Text style={styles.secureTxt}>Run the privacy checkup and set an app lock. Nothing is pre-set — every control is yours.</Text>
          <View style={{ flexDirection: 'row', gap: 10, marginTop: 10 }}>
            <TouchableOpacity style={styles.secureBtn} onPress={onRunCheckup}>
              <Text style={styles.secureBtnTxt}>Run the privacy checkup</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.secureBtnGhost} onPress={onDismissSecurePrompt}>
              <Text style={styles.secureBtnGhostTxt}>Not now</Text>
            </TouchableOpacity>
          </View>
        </View>
      ) : null}

      <View style={styles.body}>
        {tab === 'sessions' ? (
          <SessionsScreen sessions={sessions} busy={busy} onRefresh={onRefreshSessions} onOpenSession={onOpenSession} onNewSession={onNewSession} onCreateInvite={onCreateInvite} onJoinInvite={onJoinInvite} welcomeVisible={welcomeVisible} onOpenWelcome={onOpenWelcome} forumBannerVisible={forumBannerVisible} forumBannerBusy={forumBannerBusy} onJoinForum={onJoinForum} onDismissForumBanner={onDismissForumBanner} />
        ) : tab === 'contacts' ? (
          <ContactsScreen contacts={contacts} busy={busy} error={contactsError} onLookup={onLookup} onPin={onPin} onUnpin={onUnpin} onMessage={onMessage} onVerify={onVerify} onSetNickname={onSetNickname} onCreateGroup={onCreateGroup} />
        ) : tab === 'vaults' ? (
          <VaultsScreen app={app} decoy={decoyMode} veilId={veilId} />
        ) : tab === 'notes' ? (
          !appLockEnabled ? (
            <View style={styles.notesGate}>
              <Text style={styles.notesGateTitle}>Notes are locked</Text>
              <Text style={styles.notesGateBody}>Notes open only behind the app passcode. Set one in Settings → App Lock, then come back.</Text>
              <TouchableOpacity style={styles.notesGateBtn} onPress={() => onTab('settings')}><Text style={styles.notesGateBtnTxt}>Go to Settings</Text></TouchableOpacity>
            </View>
          ) : !notesUnlocked ? (
            <View style={styles.notesGate}>
              <Text style={styles.notesGateTitle}>Notes are locked</Text>
              <Text style={styles.notesGateBody}>Enter your app passcode to open Notes.</Text>
              <TextInput style={styles.notesGateInput} secureTextEntry keyboardType="number-pad" maxLength={12} value={notesCode} onChangeText={setNotesCode} onSubmitEditing={unlockNotes} placeholder="••••" placeholderTextColor="#3b4b56" />
              {notesErr ? <Text style={styles.notesGateErr}>{notesErr}</Text> : null}
              <TouchableOpacity style={styles.notesGateBtn} disabled={notesBusy} onPress={unlockNotes}><Text style={styles.notesGateBtnTxt}>{notesBusy ? 'Checking…' : 'Unlock Notes'}</Text></TouchableOpacity>
            </View>
          ) : (
            <NotesScreen app={app} decoy={decoyMode} veilId={veilId} />
          )
        ) : tab === 'stego' ? (
          <StegoScreen storage={app.storage} />
        ) : (
          <SettingsScreen
            settings={settings} onChange={onSettingsChange} veilId={veilId} email={email}
            onRunCheckup={onRunCheckup} appLockEnabled={appLockEnabled}
            onSetAppLock={onSetAppLock} onRemoveAppLock={onRemoveAppLock}
            onSignOut={onSignOut} onLockNow={onLockNow} onWipeDevice={onWipeDevice}
            onDeleteAccount={onDeleteAccount} onViewIntro={onViewIntro} onOpenWelcome={onOpenWelcome} webBaseUrl={webBaseUrl}
            onOpenTools={() => onTab('vaults')} onOpenContacts={() => onTab('contacts')}
            onCreateTransfer={onCreateTransfer} onReceiveTransfer={onReceiveTransfer}
            onVerifyPhrase={onVerifyPhrase} onRemoveIdentity={onRemoveIdentity}
            onGenerateNewVeilId={onGenerateNewVeilId} onCreateIdentity={onCreateIdentity}
          />
        )}
      </View>

      {/* (b118) owner request (Sept 24): the 'account: <email>' line is gone — Settings must never show the signed-in identity/email. */}
      {/* (b67) owner request: Chat - Contacts - Vault - Stego - Notes - Settings */}
      <View style={styles.bottomBar}>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('sessions')}>
          <View>
            {tabIcon(tab === 'sessions' ? 'chatbubble' : 'chatbubble-outline', tab === 'sessions')}
            {unreadTotal > 0 ? (
              <View style={styles.tabBadge}><Text style={styles.tabBadgeText}>{unreadTotal > 9 ? '9+' : unreadTotal}</Text></View>
            ) : null}
          </View>
          <Text style={[styles.bottomLabel, tab === 'sessions' && styles.bottomLabelOn]}>Chat</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('contacts')}>
          {tabIcon(tab === 'contacts' ? 'person' : 'person-outline', tab === 'contacts')}
          <Text style={[styles.bottomLabel, tab === 'contacts' && styles.bottomLabelOn]}>Contacts</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('vaults')}>
          {tabIcon(tab === 'vaults' ? 'lock-closed' : 'lock-closed-outline', tab === 'vaults')}
          <Text style={[styles.bottomLabel, tab === 'vaults' && styles.bottomLabelOn]}>Vault</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('stego')}>
          {tabIcon(tab === 'stego' ? 'images' : 'images-outline', tab === 'stego')}
          <Text style={[styles.bottomLabel, tab === 'stego' && styles.bottomLabelOn]}>Stego</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('notes')}>
          {tabIcon(tab === 'notes' ? 'document-text' : 'document-text-outline', tab === 'notes')}
          <Text style={[styles.bottomLabel, tab === 'notes' && styles.bottomLabelOn]}>Notes</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('settings')}>
          {tabIcon(tab === 'settings' ? 'settings' : 'settings-outline', tab === 'settings')}
          <Text style={[styles.bottomLabel, tab === 'settings' && styles.bottomLabelOn]}>Settings</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  // b198 Notes gate — the passcode prompt covering the Notes tab
  notesGate: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 32, backgroundColor: '#0b141a' },
  notesGateTitle: { fontSize: 20, fontWeight: '700', color: '#e8f1f2', marginBottom: 10 },
  notesGateBody: { fontSize: 14, color: '#8ba1ad', textAlign: 'center', marginBottom: 22, lineHeight: 20 },
  notesGateInput: { width: 180, padding: 12, borderRadius: 10, backgroundColor: '#14212b', color: '#e8f1f2', textAlign: 'center', fontSize: 18, letterSpacing: 6, marginBottom: 12 },
  notesGateBtn: { paddingVertical: 12, paddingHorizontal: 28, borderRadius: 10, backgroundColor: '#123f36' },
  notesGateBtnTxt: { color: '#7cf4c8', fontWeight: '700' },
  notesGateErr: { color: '#ff8a8a', marginBottom: 12 },
  secureBox: { borderWidth: 1, borderColor: '#7cf4c8', borderRadius: 10, padding: 12, marginHorizontal: 14, marginTop: 8, marginBottom: 4, backgroundColor: 'rgba(124,244,200,0.04)' },
  secureTitle: { color: '#7cf4c8', fontSize: 13, fontWeight: '800', marginBottom: 4 },
  secureTxt: { color: '#7a8b96', fontSize: 11, lineHeight: 15 },
  secureBtn: { backgroundColor: '#7cf4c8', borderRadius: 8, paddingHorizontal: 12, paddingVertical: 8 },
  secureBtnTxt: { color: '#06231c', fontWeight: '800', fontSize: 12 },
  secureBtnGhost: { borderWidth: 1, borderColor: '#2a3b46', borderRadius: 8, paddingHorizontal: 12, paddingVertical: 8 },
  secureBtnGhostTxt: { color: '#7a8b96', fontSize: 12 },
  fill: { flex: 1, backgroundColor: '#0b0f14' },
  // "VEIL nice and visible top-left" (Sept 19): bigger logo mark + wider
  // letter-spacing, matches the target mock's prominent wordmark.
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 20, paddingTop: 18, paddingBottom: 16, borderBottomWidth: 1, borderBottomColor: '#141d25' },
  brandRow: { flexDirection: 'row', alignItems: 'center' },
  logoSmall: { width: 34, height: 34, marginRight: 11 },
  logo: { color: '#7cf4c8', fontSize: 22, fontWeight: '800', letterSpacing: 7 },
  signOut: { color: '#5a6b76', fontSize: 13 },
  identityStrip: { paddingHorizontal: 20, paddingTop: 12, paddingBottom: 4 },
  // Owner request (Sept 19): Veil ID itself reads BLUE, the keychain
  // subtitle reads YELLOW (same yellow family as the Tools descriptions).
  veilId: { color: '#7cf4c8', fontSize: 12, letterSpacing: 0.5 },
  veilIdRow: { flexDirection: 'row', alignItems: 'center', gap: 6 },
  idDot: { width: 7, height: 7, borderRadius: 3.5, backgroundColor: '#35d07f' }, // b57 green status dot
  ok: { color: '#8a6d3b', fontSize: 11, marginTop: 3 },
  body: { flex: 1 },
  // Bottom icon tab bar (Sept 19): moved from top-of-screen text tabs to a
  // standard bottom nav bar with icon + label, matching the target mock.
  // SafeAreaView already wraps the whole app (b46 notch fix), so this bar
  // naturally clears the home-indicator area on notched iPhones.
  bottomBar: { flexDirection: 'row', borderTopWidth: 1, borderTopColor: '#141d25', backgroundColor: '#0b0f14', paddingTop: 8, paddingBottom: 6 },
  bottomTab: { flex: 1, alignItems: 'center', gap: 3 },
  // b90: unread badge pinned to the top-right of the Chat tab icon
  tabBadge: { position: 'absolute', top: -6, right: -12, backgroundColor: '#7cf4c8', borderRadius: 9, minWidth: 18, paddingHorizontal: 5, paddingVertical: 2, alignItems: 'center', justifyContent: 'center' },
  tabBadgeText: { color: '#06231c', fontSize: 10, fontWeight: '800' },
  bottomLabel: { color: '#4a5b66', fontSize: 10, fontWeight: '600' },
  bottomLabelOn: { color: '#7cf4c8' },
});
