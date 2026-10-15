import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet, ScrollView, RefreshControl, Alert, Share, ActivityIndicator, Image } from 'react-native';
import { useThemedPrompt } from './ThemedPrompt';

export interface SessionRow {
  token: string;
  /** relay VeilSession record id (for hard-delete fallbacks when the end gate 403s) */
  recId?: string;
  /** Display name: contact nickname, else peer veil-id, else 'Anonymous session'. */
  title: string;
  subtitle: string;
  status: 'active' | 'pending' | 'ended';
  verified: boolean;
  unread: number;
  /** role-aware PEER veil-id (the other party), for re-session actions */
  peerVeilId?: string;
  /** MY side completed the per-session verify ceremony */
  myVerified?: boolean;
  /** the PEER's side completed it */
  peerVerified?: boolean;
  /** b155: contact (pinned) session — trust comes from the pin, no ceremony state */
  contact?: boolean;
  /** b178: true when this account was the INITIATOR (we created it) — the
   *  new-invite banner must not fire for our own creations. */
  mine?: boolean;
  /** b162: PEER's last presence beat (relay seen_at, ms epoch; 0 = never seen).
   *  Web parity: fresh within 15 s reads as online. Groups never carry this. */
  peerSeenAt?: number;
  /** b62 groups: set when this row is a veil-group-1 thread */
  groupToken?: string;
  /** b71 dedupe (internal, never rendered): true when this row is the
   *  group's MAIN session — mine AND no peer on the row. Used by
   *  collapseGroupRows() to prefer the canonical thread over invite rows. */
  mainGroupRow?: boolean;

  /** b187/b188: lounge/forum thread — local record, no invite session.
   *  lounge = founder broadcast (read-only); forum = writable. */
  lounge?: boolean;
  forum?: boolean;
}

export interface SessionsScreenProps {
  sessions: SessionRow[];
  busy: boolean;
  onRefresh: () => void;
  onOpenSession: (token: string) => void;
  /** one-tap session: jump to pinned contacts */
  onNewSession: () => void;
  /** web parity: create a pending invite session, return the shareable link */
  onCreateInvite: () => Promise<string>;
  /** web parity: join a session from a pasted invite link */
  onJoinInvite: (link: string) => Promise<void>;
  /** b139 funnel fix: pinned local welcome thread (shown until dismissed) */
  welcomeVisible?: boolean;
  onOpenWelcome?: () => void;
  /** b196-r5: Founding Tester Forum banner (non-members only) */
  forumBannerVisible?: boolean;
  forumBannerBusy?: boolean;
  onJoinForum?: () => void;
  onDismissForumBanner?: () => void;
}

/**
 * Conversations list (Phase B step 4). Rows come from the relay session list
 * joined with local ratchet state; opening a row mounts the chat pane (next step).
 */
export function SessionsScreen({ sessions, busy, onRefresh, onOpenSession, onNewSession, onCreateInvite, onJoinInvite, welcomeVisible, onOpenWelcome, forumBannerVisible, forumBannerBusy, onJoinForum, onDismissForumBanner }: SessionsScreenProps) {
  const [inviteBusy, setInviteBusy] = React.useState(false);
  const [inviteLink, setInviteLink] = React.useState<string | null>(null);
  // BUG FIXED (Sept 19): "+ New" used to open ActionSheetIOS — a plain system
  // sheet that renders in iOS's own light/system styling, not VEIL's palette.
  // Replaced with an in-screen overlay (same pattern already proven for
  // ChatScreen's preview dialog) so it's themed and can't collide with
  // another native modal.
  const [pickerOpen, setPickerOpen] = React.useState(false);
  // (b57) themed prompt — the OS Alert.prompt here was an unthemeable system box
  const { node: promptNode, ask } = useThemedPrompt();

  const onNew = () => setPickerOpen(true);

  const doJoinPrompt = async () => {
    const t = (await ask({
      title: 'Join with an invite link',
      message: 'Paste the link your peer sent you.',
      input: 'text',
      submitLabel: 'Join',
    })) as string | null;
    const link = (t || '').trim();
    if (!link) return;
    setInviteBusy(true);
    try {
      await onJoinInvite(link);
    } catch (e) {
      await ask({ title: 'Could not join', message: String((e as Error).message || e), info: true });
    } finally {
      setInviteBusy(false);
    }
  };

  const doCreateInvite = async () => {
    setInviteBusy(true); setInviteLink(null);
    try { setInviteLink(await onCreateInvite()); } catch (e) {
      Alert.alert('Invite could not be created', String((e as Error).message || e));
    } finally { setInviteBusy(false); }
  };

  return (
    <View style={styles.fill}>
      <View style={styles.topBar}>
        <Text style={styles.h1}>Conversations</Text>
        <TouchableOpacity style={styles.newBtn} onPress={onNew} disabled={inviteBusy}>
          {inviteBusy ? <ActivityIndicator color="#7cf4c8" size="small" /> : <Text style={styles.newBtnText}>＋ New</Text>}
        </TouchableOpacity>
      </View>

      {pickerOpen ? (
        <View style={styles.pickerOverlay}>
          <TouchableOpacity style={styles.pickerBackdrop} activeOpacity={1} onPress={() => setPickerOpen(false)} />
          <View style={styles.pickerCard}>
            <Text style={styles.pickerTitle}>Start a conversation</Text>
            <TouchableOpacity style={styles.pickerRow} onPress={() => { setPickerOpen(false); onNewSession(); }}>
              <Text style={styles.pickerRowTxt}>One-tap session with a pinned contact</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.pickerRow} onPress={() => { setPickerOpen(false); doCreateInvite(); }}>
              <Text style={styles.pickerRowTxt}>Create an invite link</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.pickerRow} onPress={() => { setPickerOpen(false); doJoinPrompt(); }}>
              <Text style={styles.pickerRowTxt}>Join with an invite link</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.pickerCancelRow} onPress={() => setPickerOpen(false)}>
              <Text style={styles.pickerCancelTxt}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      ) : null}

      <ScrollView
        style={styles.fill}
        contentContainerStyle={sessions.length === 0 ? styles.emptyWrap : styles.list}
        refreshControl={<RefreshControl tintColor="#5fd4c4" refreshing={busy} onRefresh={onRefresh} />}
      >
        {inviteLink ? (
          <View style={styles.inviteCard}>
            <Text style={styles.inviteTitle}>Invite link ready</Text>
            <Text style={styles.inviteText}>
              Share it with one person. It opens the VEIL web app, and the key lives only in the link. The conversation unlocks when they join.
            </Text>
            <TouchableOpacity style={styles.inviteBtn} onPress={() => Share.share({ message: inviteLink }).catch(() => {})}>
              <Text style={styles.inviteBtnTxt}>Share / copy the link</Text>
            </TouchableOpacity>
            <TouchableOpacity onPress={() => setInviteLink(null)}>
              <Text style={styles.inviteDismiss}>Dismiss</Text>
            </TouchableOpacity>
          </View>
        ) : null}
        {forumBannerVisible ? (
          <View style={styles.forumBanner}>
            <Text style={styles.forumBannerTitle}>⚡ The Founding Tester Forum is live — from Matt, your founder</Text>
            <Text style={styles.forumBannerBody}>Big news: we've upgraded VEIL's security and moved to our own servers and relay. The Founding Tester Forum is where I'll be talking with you all directly — one tap to join, no invite link, end-to-end encrypted, history kept for 30 days. To use it you'll need to migrate over to the new native build — the upgrade only runs there. Come across, say hello — look forward to talking to you all. — Matt</Text>
            <View style={styles.forumBannerActions}>
              <TouchableOpacity style={styles.forumJoinBtn} onPress={onJoinForum} disabled={forumBannerBusy || busy}>
                <Text style={styles.forumJoinBtnText}>{forumBannerBusy ? 'Joining…' : 'Join the forum →'}</Text>
              </TouchableOpacity>
              <TouchableOpacity onPress={onDismissForumBanner} disabled={forumBannerBusy}>
                <Text style={styles.forumBannerDismiss}>Not now</Text>
              </TouchableOpacity>
            </View>
          </View>
        ) : null}
        {welcomeVisible && onOpenWelcome ? (
          <TouchableOpacity style={styles.welcomeRow} onPress={onOpenWelcome} disabled={busy}>
            <View style={[styles.avatar, styles.avatarWelcome]}>
              <Text style={styles.avatarText}>VE</Text>
            </View>
            <View style={styles.rowBody}>
              <View style={styles.rowTop}>
                <Text style={styles.rowTitle} numberOfLines={1}>Getting started</Text>
              </View>
              <Text style={styles.rowSub} numberOfLines={1}>A welcome note from Matt, plus your first three moves.</Text>
            </View>
            <Text style={styles.chevron}>›</Text>
          </TouchableOpacity>
        ) : null}
        {sessions.length === 0 ? (
          <View style={styles.empty}>
            {/* Big, visible brand mark for the empty state — owner reverted the
                glow box (Sept 19): just the ring/arcs, no background/shadow. */}
            <Image source={require('../../assets/logo-mark.png')} style={styles.emptyLogo} resizeMode="contain" />
            <Text style={styles.emptyTitle}>No conversations yet</Text>
            <Text style={styles.emptyText}>
              Start a one-tap session from a pinned contact, or share an invite link. Messages are sealed with post-quantum keys that never leave this device.
            </Text>
          </View>
        ) : (
          sessions.map((s) => (
            <TouchableOpacity key={s.token} style={styles.row} onPress={() => onOpenSession(s.token)} disabled={busy}>
              <View style={[styles.avatar, s.status === 'pending' && styles.avatarPending]}>
                <Text style={styles.avatarText}>{s.title.slice(0, 2).toUpperCase()}</Text>
              </View>
              <View style={styles.rowBody}>
                <View style={styles.rowTop}>
                  <Text style={styles.rowTitle} numberOfLines={1}>{s.title}</Text>
                  {s.verified ? <Text style={styles.verified}>✓ verified</Text> : null}
                </View>
                <Text style={styles.rowSub} numberOfLines={1}>{s.subtitle}</Text>
              </View>
              {s.unread > 0 ? (
                <View style={styles.badge}><Text style={styles.badgeText}>{s.unread > 9 ? '9+' : s.unread}</Text></View>
              ) : (
                <Text style={styles.chevron}>›</Text>
              )}
            </TouchableOpacity>
          ))
        )}
      </ScrollView>
      {promptNode}
    </View>
  );
}

const styles = StyleSheet.create({
  pickerOverlay: { position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, justifyContent: 'flex-end', zIndex: 20 },
  pickerBackdrop: { position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.55)' },
  pickerCard: { backgroundColor: '#111820', borderTopLeftRadius: 16, borderTopRightRadius: 16, borderWidth: 1, borderColor: '#1d2733', borderBottomWidth: 0, paddingTop: 14, paddingBottom: 28, paddingHorizontal: 16 },
  pickerTitle: { color: '#5a6b76', fontSize: 12, fontWeight: '600', textAlign: 'center', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 0.5 },
  pickerRow: { paddingVertical: 15, borderTopWidth: 1, borderTopColor: '#1d2733', alignItems: 'center' },
  pickerRowTxt: { color: '#7cf4c8', fontSize: 15, fontWeight: '600' },
  pickerCancelRow: { paddingVertical: 15, marginTop: 8, borderRadius: 10, backgroundColor: '#1a2229', alignItems: 'center' },
  pickerCancelTxt: { color: '#e6eef2', fontSize: 15, fontWeight: '600' },
  welcomeRow: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#12211d', borderWidth: 1, borderColor: '#1f4a42', borderRadius: 12, padding: 14, marginBottom: 14 },
  avatarWelcome: { backgroundColor: '#123c34' },
  inviteCard: { borderWidth: 1, borderColor: '#1f4a42', borderRadius: 12, padding: 14, marginBottom: 14, backgroundColor: 'rgba(124,244,200,0.05)' },
  // b198 (owner): the Founding Tester Forum banner in FLUORO BLUE — it is the
  // home-page announcement and must be unmissable.
  forumBanner: { borderWidth: 2, borderColor: '#7cf4c8', borderRadius: 12, padding: 14, marginBottom: 14, backgroundColor: 'rgba(124,244,200,0.12)' },
  forumBannerTitle: { color: '#7cf4c8', fontSize: 15, fontWeight: '800', marginBottom: 6 },
  forumBannerBody: { color: '#cfe6de', fontSize: 12, lineHeight: 18, marginBottom: 10 },
  forumBannerActions: { flexDirection: 'row', alignItems: 'center', gap: 14 },
  forumJoinBtn: { backgroundColor: '#7cf4c8', borderRadius: 10, paddingVertical: 10, paddingHorizontal: 16 },
  forumJoinBtnText: { color: '#0b141a', fontSize: 13, fontWeight: '800' },
  forumBannerDismiss: { color: '#9db3ad', fontSize: 12 },
  inviteTitle: { color: '#e6eef2', fontSize: 14, fontWeight: '600', marginBottom: 6 },
  inviteText: { color: '#9db3ad', fontSize: 12, lineHeight: 17, marginBottom: 10 },
  inviteBtn: { backgroundColor: '#123c34', borderRadius: 10, paddingVertical: 10, alignItems: 'center', marginBottom: 8 },
  inviteBtnTxt: { color: '#7cf4c8', fontSize: 13, fontWeight: '600' },
  inviteDismiss: { color: '#5fd4c4', fontSize: 12, textAlign: 'center', paddingVertical: 2 },
  fill: { flex: 1 },
  topBar: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 20, paddingTop: 16, paddingBottom: 12 },
  h1: { color: '#e6eef2', fontSize: 22, fontWeight: '700' },
  newBtn: { backgroundColor: '#12211d', borderRadius: 8, borderWidth: 1, borderColor: '#1f4a42', paddingHorizontal: 12, paddingVertical: 7 },
  newBtnText: { color: '#7cf4c8', fontSize: 13, fontWeight: '600' },
  list: { paddingHorizontal: 12, paddingBottom: 24 },
  emptyWrap: { flex: 1, justifyContent: 'center' },
  empty: { alignItems: 'center', paddingHorizontal: 40 },
  // Big glowing ring logo, centered (Sept 19 mock request) — shadow-based
  // "glow" since RN has no CSS blur filter; a large soft shadow radius on a
  // dark background reads as the same effect.
  emptyLogoGlow: {
    width: 150, height: 150, borderRadius: 75, marginBottom: 22,
    alignItems: 'center', justifyContent: 'center',
    backgroundColor: 'rgba(124,244,200,0.06)',
    shadowColor: '#7cf4c8', shadowOpacity: 0.33, shadowRadius: 24, shadowOffset: { width: 0, height: 0 }, // b57: glow lightened per owner; ring asset untouched
    elevation: 12,
  },
  emptyLogo: { width: 96, height: 96, marginBottom: 22 },
  emptyTitle: { color: '#e6eef2', fontSize: 16, fontWeight: '600', marginBottom: 8 },
  emptyText: { color: '#5a6b76', fontSize: 13, lineHeight: 19, textAlign: 'center' },
  row: { flexDirection: 'row', alignItems: 'center', padding: 14, borderRadius: 14, marginBottom: 8, backgroundColor: '#0e151c', borderWidth: 1, borderColor: '#162029' },
  avatar: { width: 44, height: 44, borderRadius: 22, backgroundColor: '#1a2f29', alignItems: 'center', justifyContent: 'center', marginRight: 12 },
  avatarPending: { backgroundColor: '#2a2413' },
  avatarText: { color: '#7cf4c8', fontSize: 15, fontWeight: '700' },
  rowBody: { flex: 1 },
  rowTop: { flexDirection: 'row', alignItems: 'center' },
  rowTitle: { color: '#e6eef2', fontSize: 15, fontWeight: '600', flexShrink: 1, marginRight: 8 },
  verified: { color: '#7cf4c8', fontSize: 11 },
  rowSub: { color: '#5a6b76', fontSize: 12, marginTop: 3 },
  badge: { backgroundColor: '#7cf4c8', borderRadius: 10, minWidth: 20, paddingHorizontal: 6, paddingVertical: 3, alignItems: 'center' },
  badgeText: { color: '#062019', fontSize: 11, fontWeight: '700' },
  chevron: { color: '#3b4b56', fontSize: 22 },
});
