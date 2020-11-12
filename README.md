# webauthn-secret

_repurposing webauthn for end-to-end-encryption and peer-to-peer digital signatures!_

an in-browser, webauthn version of https://jbp.io/2015/11/23/abusing-u2f-to-store-keys.html

enables creating and retrieving an opaque secret string from a hardware authenticator (optionally protected by an additional password).

depends on `elliptic` for key recovery (=> no guaranteed timing attacks safety)

DISCLAIMER: i'm no security expert

_probably more secure than:_

- hand-typed passwords
- browser-filled passwords (which are ultimately accessible from the file system)
- storing plain text keys in the file system (e.g. signal desktop)
- storing the material to derive keys from a password in the file system (e.g. metamask)
- storing stuff on a server which can be accessed by any of these mechanisms

_less secure than:_

- webauthn as it was intended, if the server itself can _only ever_ be remotely accessed by a webauthn-like mechanism (e.g. ssh with a fido2 key), and you unconditionally trust the people who operate the server

the attack vector that this doesn't prevent, but proper webauthn does, is that a user's device is controlled by an attacker during key usage, and a side channel attack is run against the in-browser key recovery.

but note that a fully attacker-controlled user device offers another attack during key usage which no auth mechanism (not even proper webauthn) can prevent: modifying the user's browser/DNS to display a phishing website instead of the website normally asking for authentication, while disabling any browser-enforced counter-measures like preventing access to webauthn from a different origin.

## usage

see `demo.html` for the API

_TODO:_ i haven't made this an npm module yet. you can, however, use it in deno or a browser `<script type="module">` by importing it directly from github through [jsdelivr](https://www.jsdelivr.com/)

```js
import {
  createSecret,
  getSecret,
} from "https://cdn.jsdelivr.net/gh/mitschabaude/webauthn-secret/dist/webauthn-secret.min.js";
```

## try it out

prerequisite: a fido2 authenticator (examples: yubikey, another usb key or android phone)

1. `npx serve` this folder
2. navigate to `http://localhost:5000/demo.html`
3. look at the console while you press the buttons

## thanks

to the creators of `indutny/elliptic`, `paroga/cbor-js` and `cryptocoinjs/base-x`, on which this package depends
