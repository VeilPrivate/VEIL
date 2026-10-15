# VEIL — Private Messenger

End-to-end encrypted messaging with post-quantum key establishment, running on infrastructure the operator controls.

**VEIL** is a privacy-focused messenger built for the moments a phone stops being private — a border stop, a search, a device seized from your hands. What sits on the device is ciphertext: no message history, no contacts, no plaintext.

## What's in this repository

| Directory | What it is |
|---|---|
| `crypto-core/` | The encryption: the ratchet, the hybrid X25519 + ML-KEM-768 key agreement, the identity system |
| `device/` | The protocol layer: sessions, groups, contacts, media, vaults, notes, calls, the relay client |
| `relay/` | The self-hosted relay server: the API, the session gate, the group gate, the sweeper |
| `modules/` | The native iOS module: hardware-accelerated PBKDF2 and AES for the app lock and the vault |
| `src/` | The React Native app: the screens, the notifications, the privacy controls |
| `app.json` | The Expo configuration |

## The security model

- **End-to-end encryption:** AES-256-GCM with a hybrid X25519 + ML-KEM-768 key establishment. The relay stores ciphertext it cannot open.
- **Post-quantum groups:** one envelope per message under per-epoch ML-KEM-768 keys.
- **Either-side kill switch:** one tap hard-deletes the thread's envelopes and the session record from the relay.
- **Nothing-at-Rest:** the identity keys live in memory only — nothing is written to storage at all.
- **Hold-until-unlock:** a locked phone fetches nothing — messages wait on the relay.

## The honest limits

- The protocol is implemented and self-reviewed, but **not independently audited**.
- Cover traffic obscures timing and size but does not provide metadata privacy against the relay operator.
- Calls are same-network only in this build (no STUN/TURN — the roadmap includes self-hosted STUN).

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

Stores ciphertext and metadata it cannot decrypt. The full security model is in the relay's source code and the threat model documentation.

## License

Copyright © 2026 Matt Franks

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
