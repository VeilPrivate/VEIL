# Vardum

**Private messaging that stays private, even if someone has your phone.**

Vardum (formerly VEIL) is an end-to-end encrypted messenger for iOS. This repository holds the crypto core, the relay server and the protocol layer, under AGPL-3.0, so anyone can check the claims against the code.

> Renamed from VEIL in October 2026. Internal identifiers (`veil_*` keys, `veil-*` crypto labels, the `VeilCrypto` module) keep their old names on purpose: changing them would break existing installs and keys.

## What it does

- **End-to-end encryption.** Hybrid X25519 + ML-KEM-768 key exchange, double ratchet, forward secrecy per message. The relay stores ciphertext it cannot open.
- **Deleted means deleted.** Burn after read (5 min to 24 h after opening), an expiry for unopened copies, and a wipe either person can trigger. Relay copies are hard-deleted, not hidden.
- **Nothing-at-Rest.** Identity keys live in memory only. A locked phone fetches nothing and holds nothing to extract. Recovery is the 24-word phrase.
- **Duress and decoy codes.** A decoy code opens a harmless dashboard. A duress code wipes local keys and server records, then shows the same decoy.
- **No phone. No email. No name.** Your identity is 24 random words made on your phone. Your Vardum ID is random, and nothing you sign up with points back to you.
- **Groups up to 100.** Post-quantum sender keys, rotation each epoch, signed membership, evictions that stick.
- **Encrypted media, vaults and notes.** Per-file keys, a hidden vault volume, a 25 MB cap.

## Honest limits

- Calls work between devices on the same network only. Internet calling is on the roadmap.
- Vardum has been self-reviewed, not independently audited.
- The relay sees network metadata such as timing, sizes and the IP address of each request. See the [privacy policy](https://tryveil.app/privacy/) for what is kept and for how long.

Every claim is listed with its evidence in the [claims register](https://tryveil.app/claims/).

## Try it

Join the iOS beta on TestFlight: https://testflight.apple.com/join/Aqay7XH2

## What's in this repository

| Directory | What it is |
|---|---|
| `crypto-core/` | The encryption: the ratchet, the hybrid X25519 + ML-KEM-768 key agreement, the identity system |
| `device/` | The protocol layer: sessions, groups, contacts, media, vaults, notes, calls, the relay client |
| `relay/` | The self-hosted relay server: the API, the session gate, the group gate, the sweeper |
| `modules/` | The native iOS module: hardware-accelerated PBKDF2 and AES for the app lock and the vault |
| `src/` | The React Native app: the screens, the notifications, the privacy controls |
| `app.json` | The Expo configuration |

## Building

Requires Node.js 18+, and for the iOS build: Xcode with an Apple developer account.

```bash
npm install
npx expo start          # development
npx eas build --platform ios --profile production  # release build
```

## The relay

The relay is a Deno application. Deploy:

```bash
cd relay
deno run -A --unstable-kv main.ts
```

Stores ciphertext it cannot decrypt. It does see network metadata — see Honest limits above. The full security model is in the relay's source code and the threat model documentation.

## License

Copyright © 2026 Matt Franks

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
