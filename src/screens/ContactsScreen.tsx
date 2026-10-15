import React, { useState } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, Share,
  ActivityIndicator, Modal,
} from 'react-native';

export interface ContactRow {
  veilId: string;
  nickname: string | null;
  verified: boolean;
  fingerprint: string;
}

export interface LookupResult {
  veilId: string;
  fingerprint: string;
  ikPubB64: string;
}

export interface ContactsScreenProps {
  contacts: ContactRow[];
  busy: boolean;
  error: string | null;
  /** Look up a veil-id on the relay (public keys only). */
  onLookup: (veilId: string) => Promise<LookupResult | null>;
  /** Pin after the user confirms the fingerprint card. */
  onPin: (lookup: LookupResult) => Promise<void>;
  /** b57: unpin — device-local trust anchor removal; two-tap confirm below. */
  onUnpin: (veilId: string) => Promise<void>;
  /** One-tap session: X3DH-style from the pinned SPK, no invite link, no ceremony. */
  onMessage: (veilId: string) => void;
  /** Mark "I compared the fingerprints" — verifies the pin. */
  onVerify: (veilId: string) => Promise<void>;
  /** Device-local nickname — never transmitted, never synced. */
  onSetNickname: (veilId: string, nickname: string) => void;
  /** b62 groups: create a group + invite links (creator flow) */
  onCreateGroup: (name: string, inviteCount: number) => Promise<{ groupName: string; inviteLinks: string[] }>;
}

/**
 * Pinned contacts + one-tap sessions (Phase B step 4).
 * The pinned identity key IS the trust anchor: pin once, message forever —
 * no invite links, no fingerprint ceremony for later sessions.
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

export function ContactsScreen({
  contacts, busy, error, onLookup, onPin, onUnpin, onMessage, onVerify, onSetNickname, onCreateGroup,
}: ContactsScreenProps) {
  // b62 groups: create flow
  const [groupName, setGroupName] = useState('');
  const [groupCount, setGroupCount] = useState(3);
  const [groupBusy, setGroupBusy] = useState(false);
  const [groupErr, setGroupErr] = useState<string | null>(null);
  const [groupCreated, setGroupCreated] = useState<{ groupName: string; inviteLinks: string[] } | null>(null);
  const [lookupInput, setLookupInput] = useState('');
  const [lookupBusy, setLookupBusy] = useState(false);
  const [lookupErr, setLookupErr] = useState<string | null>(null);
  const [card, setCard] = useState<LookupResult | null>(null);
  const [nickFor, setNickFor] = useState<string | null>(null);
  const [unpinArm, setUnpinArm] = useState<string | null>(null);
  const [nickInput, setNickInput] = useState('');

  /** web parity: two-tap unpin confirm — first tap arms the button for 6 s. */
  const doUnpin = async (veilId: string) => {
    if (unpinArm === veilId) {
      setUnpinArm(null);
      try { await onUnpin(veilId); } catch { /* surfaced by parent */ }
      return;
    }
    setUnpinArm(veilId);
    setTimeout(() => setUnpinArm((a) => (a === veilId ? null : a)), 6000);
  };

  const doLookup = async () => {
    setLookupBusy(true); setLookupErr(null);
    try {
      const r = await onLookup(lookupInput.trim());
      if (r) setCard(r); else setLookupErr('No Veil identity matches that id.');
    } catch (e) {
      setLookupErr(friendlyError(e, 'lookup'));
    } finally { setLookupBusy(false); }
  };

  return (
    <View style={styles.fill}>
      <ScrollView style={styles.fill} contentContainerStyle={styles.wrap}>
        <Text style={styles.h1}>Contacts</Text>
        <Text style={styles.h2}>
          Pins are device-local trust anchors: the pinned key IS the identity. Nicknames never leave this device.
        </Text>

        {/* b62 groups: create a group (creator flow — invite links after) */}
        <View style={styles.groupBox}>
          <Text style={styles.groupTitle}>Create a group</Text>
          <Text style={styles.groupHint}>
            Post-quantum group chat (up to 8 members). You get one invite link per seat — the group key lives only in the links.
          </Text>
          <TextInput
            style={styles.groupInput}
            autoCapitalize="words"
            autoCorrect={false}
            placeholder="Group name…"
            placeholderTextColor="#3b4b56"
            value={groupName}
            editable={!groupBusy}
            onChangeText={(t) => { setGroupName(t); setGroupErr(null); }}
          />
          <View style={styles.groupCountRow}>
            <Text style={styles.groupCountLbl}>Invite links</Text>
            {[1, 2, 3, 5, 7].map((n) => (
              <TouchableOpacity
                key={n}
                style={[styles.groupCountBtn, groupCount === n && styles.groupCountOn]}
                disabled={groupBusy}
                onPress={() => setGroupCount(n)}
              >
                <Text style={[styles.groupCountTxt, groupCount === n && styles.groupCountTxtOn]}>{n}</Text>
              </TouchableOpacity>
            ))}
            <TouchableOpacity
              style={[styles.groupCreateBtn, (!groupName.trim() || groupBusy) && styles.btnDisabled]}
              disabled={!groupName.trim() || groupBusy}
              onPress={async () => {
                setGroupBusy(true); setGroupErr(null);
                try {
                  const created = await onCreateGroup(groupName, groupCount);
                  setGroupCreated(created); setGroupName('');
                } catch (e) {
                  setGroupErr(friendlyError(e, 'group'));
                } finally { setGroupBusy(false); }
              }}
            >
              {groupBusy ? <ActivityIndicator color="#062019" /> : <Text style={styles.groupCreateBtnTxt}>Create</Text>}
            </TouchableOpacity>
          </View>
          {groupErr ? <Text style={styles.err}>{groupErr}</Text> : null}
        </View>
        {groupCreated ? (
          <View style={styles.groupBox}>
            <Text style={styles.groupTitle}>{groupCreated.groupName} is ready</Text>
            <Text style={styles.groupHint}>
              Share each link with one person (iMessage, AirDrop, in person). The conversation unlocks when they join. The name and keys travel only in the links.
            </Text>
            {groupCreated.inviteLinks.map((lnk, i) => (
              <View key={i} style={styles.groupLinkRow}>
                <Text style={styles.groupLinkTxt} numberOfLines={1}>{lnk}</Text>
                <TouchableOpacity style={styles.lookupBtn} onPress={() => Share.share({ message: lnk }).catch(() => {})}>
                  <Text style={styles.lookupBtnText}>Share</Text>
                </TouchableOpacity>
              </View>
            ))}
            <TouchableOpacity style={styles.groupDoneBtn} onPress={() => setGroupCreated(null)}>
              <Text style={styles.groupDoneTxt}>Done</Text>
            </TouchableOpacity>
          </View>
        ) : null}

        {/* (b119) owner request (Sept 24): the search / add veil-id bar was easy
            to miss — now it sits inside a teal-bordered section card with an
            uppercase title, matching the Settings section style. */}
        <View style={styles.pinCard}>
          <Text style={styles.pinCardTitle}>Add a contact</Text>
          <View style={styles.lookup}>
          <TextInput
            style={styles.lookupInput}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="Paste a veil-id to pin…"
            placeholderTextColor="#3b4b56"
            value={lookupInput}
            editable={!lookupBusy}
            onChangeText={(t) => { setLookupInput(t); setLookupErr(null); }}
          />
          <TouchableOpacity
            style={[styles.lookupBtn, lookupInput.length < 8 && styles.btnDisabled]}
            disabled={lookupInput.length < 8 || lookupBusy}
            onPress={doLookup}
          >
            {lookupBusy ? <ActivityIndicator color="#062019" /> : <Text style={styles.lookupBtnText}>Pin</Text>}
          </TouchableOpacity>
          </View>
          <Text style={styles.pinCardHint}>Search or paste a veil-id to pin a contact and enable one-tap sessions.</Text>
        </View>
        {lookupErr ? <Text style={styles.err}>{lookupErr}</Text> : null}
        {error ? <Text style={styles.err}>{error}</Text> : null}

        <Text style={styles.pinCardTitle}>Pinned contacts{contacts.length > 0 ? ` (${contacts.length})` : ''}</Text>
        {contacts.length === 0 ? (
          <Text style={styles.none}>No pinned contacts yet. Pin someone's veil-id to enable one-tap sessions.</Text>
        ) : (
          contacts.map((c) => (
            <View key={c.veilId} style={styles.card}>
              <View style={styles.cardTop}>
                <View style={[styles.avatar, c.verified && styles.avatarV]}>
                  <Text style={styles.avatarText}>{(c.nickname || c.veilId).slice(0, 2).toUpperCase()}</Text>
                </View>
                <View style={styles.cardBody}>
                  <Text style={styles.name} numberOfLines={1}>{c.nickname || c.veilId}</Text>
                  <Text style={styles.fp} numberOfLines={1}>{c.fingerprint}</Text>
                  {c.verified ? (
                    <Text style={styles.verified}>✓ fingerprint compared</Text>
                  ) : (
                    <TouchableOpacity onPress={() => onVerify(c.veilId)} disabled={busy}>
                      <Text style={styles.verifyLink}>I compared the fingerprint</Text>
                    </TouchableOpacity>
                  )}
                </View>
              </View>
              <View style={styles.cardActions}>
                <TouchableOpacity style={styles.msgBtn} onPress={() => onMessage(c.veilId)} disabled={busy}>
                  <Text style={styles.msgBtnText}>⚡ Message</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={styles.nickBtn}
                  onPress={() => { setNickFor(c.veilId); setNickInput(c.nickname || ''); }}
                >
                  <Text style={styles.nickBtnText}>{c.nickname ? 'Rename' : 'Nickname'}</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[styles.nickBtn, unpinArm === c.veilId && styles.unpinArmBtn]}
                  onPress={() => { void doUnpin(c.veilId); }}
                  disabled={busy}
                >
                  <Text style={[styles.nickBtnText, unpinArm === c.veilId && styles.unpinArmText]}>
                    {unpinArm === c.veilId ? 'Unpin?' : 'Unpin'}
                  </Text>
                </TouchableOpacity>
              </View>
            </View>
          ))
        )}
      </ScrollView>

      {/* fingerprint confirm card */}
      <Modal transparent visible={card !== null} animationType="fade" onRequestClose={() => setCard(null)}>
        <View style={styles.modalWrap}>
          <View style={styles.modal}>
            <Text style={styles.modalTitle}>Pin this key?</Text>
            <Text style={styles.modalBody}>
              Compare this fingerprint with your contact over a channel you trust. Pinning means this key is their identity from now on.
            </Text>
            <Text style={styles.fpCard}>{card?.fingerprint}</Text>
            <View style={styles.modalActions}>
              <TouchableOpacity style={styles.btnGhost} onPress={() => setCard(null)}>
                <Text style={styles.btnGhostText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.btnTeal}
                onPress={async () => {
                  if (!card) return;
                  await onPin(card);
                  setCard(null); setLookupInput('');
                }}
              >
                <Text style={styles.btnTealText}>Pin this key</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      {/* nickname modal */}
      <Modal transparent visible={nickFor !== null} animationType="fade" onRequestClose={() => setNickFor(null)}>
        <View style={styles.modalWrap}>
          <View style={styles.modal}>
            <Text style={styles.modalTitle}>Nickname</Text>
            <Text style={styles.modalBody}>Stored on this device only. Never transmitted, never synced, never on the server.</Text>
            <TextInput
              style={styles.nickInput}
              placeholder="e.g. Jo"
              placeholderTextColor="#3b4b56"
              value={nickInput}
              onChangeText={setNickInput}
            />
            <View style={styles.modalActions}>
              <TouchableOpacity style={styles.btnGhost} onPress={() => setNickFor(null)}>
                <Text style={styles.btnGhostText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.btnTeal}
                onPress={() => { if (nickFor) { onSetNickname(nickFor, nickInput.trim()); setNickFor(null); } }}
              >
                <Text style={styles.btnTealText}>Save</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1 },
  wrap: { padding: 20, paddingBottom: 32 },
  h1: { color: '#e6eef2', fontSize: 22, fontWeight: '700' },
  h2: { color: '#5a6b76', fontSize: 12, lineHeight: 17, marginTop: 6, marginBottom: 16 },
  lookup: { flexDirection: 'row' },
  pinCard: { borderWidth: 1, borderColor: '#1f4a42', borderRadius: 12, padding: 14, marginBottom: 16, backgroundColor: '#0c141c' },
  pinCardTitle: { color: '#7cf4c8', fontSize: 12, fontWeight: '800', letterSpacing: 0.6, textTransform: 'uppercase', marginBottom: 10 },
  pinCardHint: { color: '#7c8a96', fontSize: 11, marginTop: 8 },
  lookupInput: { flex: 1, color: '#e6eef2', backgroundColor: '#0e151c', borderWidth: 1, borderColor: '#223039', borderRadius: 10, paddingHorizontal: 12, paddingVertical: 10, fontSize: 14 },
  lookupBtn: { marginLeft: 8, backgroundColor: '#7cf4c8', borderRadius: 10, paddingHorizontal: 16, alignItems: 'center', justifyContent: 'center' },
  lookupBtnText: { color: '#062019', fontWeight: '700', fontSize: 14 },
  btnDisabled: { opacity: 0.35 },
  // b62 groups
  groupBox: { backgroundColor: '#0B1018', borderColor: '#1d2a38', borderWidth: 1, borderRadius: 12, padding: 12, marginBottom: 14 },
  groupTitle: { color: '#EAF2F6', fontSize: 14, fontWeight: '700', marginBottom: 4 },
  groupHint: { color: '#7c8a96', fontSize: 11, marginBottom: 10 },
  groupInput: { backgroundColor: '#080d14', borderColor: '#1d2a38', borderWidth: 1, borderRadius: 10, color: '#EAF2F6', paddingHorizontal: 10, paddingVertical: 8, marginBottom: 8 },
  groupCountRow: { flexDirection: 'row', alignItems: 'center', flexWrap: 'wrap' },
  groupCountLbl: { color: '#7c8a96', fontSize: 12, marginRight: 4 },
  groupCountBtn: { borderColor: '#1d2a38', borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 4, marginRight: 6 },
  groupCountOn: { borderColor: '#7cf4c8' },
  groupCountTxt: { color: '#7c8a96', fontSize: 12 },
  groupCountTxtOn: { color: '#7cf4c8' },
  groupCreateBtn: { backgroundColor: '#7cf4c8', borderRadius: 8, paddingHorizontal: 14, paddingVertical: 6, marginLeft: 8 },
  groupCreateBtnTxt: { color: '#062019', fontSize: 12, fontWeight: '700' },
  groupLinkRow: { flexDirection: 'row', alignItems: 'center', borderColor: '#16202c', borderWidth: StyleSheet.hairlineWidth, borderRadius: 8, paddingHorizontal: 8, paddingVertical: 4, marginBottom: 6 },
  groupLinkTxt: { color: '#8fa3b0', fontSize: 10, flex: 1, marginRight: 8 },
  groupDoneBtn: { alignItems: 'center', paddingVertical: 8 },
  groupDoneTxt: { color: '#5fd4c4', fontSize: 12 },
  err: { color: '#ff8f8f', fontSize: 12, marginTop: 4, marginBottom: 8 },
  none: { color: '#41505b', fontSize: 13, marginTop: 18, lineHeight: 18 },
  card: { backgroundColor: '#0e151c', borderWidth: 1, borderColor: '#162029', borderRadius: 14, padding: 14, marginTop: 10 },
  cardTop: { flexDirection: 'row', alignItems: 'center' },
  avatar: { width: 42, height: 42, borderRadius: 21, backgroundColor: '#1a2f29', alignItems: 'center', justifyContent: 'center', marginRight: 12 },
  avatarV: { backgroundColor: '#12332b' },
  avatarText: { color: '#7cf4c8', fontSize: 14, fontWeight: '700' },
  cardBody: { flex: 1 },
  name: { color: '#e6eef2', fontSize: 15, fontWeight: '600' },
  fp: { color: '#41505b', fontSize: 11, marginTop: 2, marginBottom: 4 },
  verified: { color: '#7cf4c8', fontSize: 11 },
  verifyLink: { color: '#7cf4c8', fontSize: 11, textDecorationLine: 'underline' },
  cardActions: { flexDirection: 'row', marginTop: 12 },
  msgBtn: { backgroundColor: '#7cf4c8', borderRadius: 9, paddingHorizontal: 16, paddingVertical: 9, marginRight: 8 },
  msgBtnText: { color: '#062019', fontWeight: '700', fontSize: 13 },
  nickBtn: { backgroundColor: '#12211d', borderWidth: 1, borderColor: '#1f4a42', borderRadius: 9, paddingHorizontal: 14, paddingVertical: 9 },
  nickBtnText: { color: '#7cf4c8', fontSize: 13, fontWeight: '600' },
  unpinArmBtn: { borderColor: '#5c2a24', borderWidth: 1 },
  unpinArmText: { color: '#e8836f' },
  modalWrap: { flex: 1, backgroundColor: 'rgba(4,7,10,0.75)', alignItems: 'center', justifyContent: 'center', padding: 28 },
  modal: { backgroundColor: '#101820', borderWidth: 1, borderColor: '#1d2a33', borderRadius: 16, padding: 22, width: '100%' },
  modalTitle: { color: '#e6eef2', fontSize: 17, fontWeight: '700' },
  modalBody: { color: '#5a6b76', fontSize: 12, lineHeight: 17, marginTop: 8, marginBottom: 14 },
  fpCard: { color: '#7cf4c8', fontSize: 15, letterSpacing: 1, backgroundColor: '#0b0f14', borderRadius: 10, borderWidth: 1, borderColor: '#1f4a42', padding: 14, marginBottom: 16 },
  modalActions: { flexDirection: 'row', justifyContent: 'flex-end' },
  btnGhost: { paddingVertical: 10, paddingHorizontal: 14, marginRight: 6 },
  btnGhostText: { color: '#5a6b76', fontSize: 14 },
  btnTeal: { backgroundColor: '#7cf4c8', borderRadius: 10, paddingVertical: 11, paddingHorizontal: 18 },
  btnTealText: { color: '#062019', fontWeight: '700', fontSize: 14 },
  nickInput: { color: '#e6eef2', backgroundColor: '#0b0f14', borderWidth: 1, borderColor: '#223039', borderRadius: 10, padding: 12, fontSize: 15, marginBottom: 16 },
});
