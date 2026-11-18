# PairingDemo

This SwiftUI app lets you try `SwiftailPairing` (QR and link pairing between apps) and Swiftail's `TailnetNode` on Mac and iPhone. One device opens an offer (the host), and another reads its QR code or link to become a paired peer (the joiner). Both roles are available on both platforms, and the node runs in the app process.

## Build

You need `xcodegen` 2.46 or later and an Xcode version that can build for macOS 15 and iOS 18 or later.

```sh
cd Examples/PairingDemo
xcodegen generate
open PairingDemo.xcodeproj
```

Run the `PairingDemo` scheme on "My Mac" or an iPhone (including a simulator).

To install on a real iPhone, copy `Config/Signing.local.xcconfig.example` to `Config/Signing.local.xcconfig` and enter the development team ID and a bundle ID prefix that team can use. This file stays out of the repository. The Mac app defaults to ad hoc signing with App Sandbox (network client and server) enabled.

## Start the node

Start in the "Node" section. There are three options.

| Option | What it does |
| --- | --- |
| Saved identity | A previously registered device reconnects automatically when you launch the app |
| Auth key | Enter the key and select "Start Node". The app does not save the key |
| Sign-in | Without a key, select "Start Node" → "Sign In in Browser" |

When the status changes to "Connected", you can see the node's name, peer count, and tailnet lock status.

## Pair two devices

Both devices must be on the same tailnet. If the joiner is not on the tailnet yet, see [Include Auth Key](#include-auth-key) below.

1. Host. Select the "Host" role and start the node. Once it is "Connected", choose a lifetime and select "Open Offer". A QR code and a link appear.
2. Joiner. Select the "Joiner" role and receive the offer. On iPhone, "Scan QR Code" is the safest option. If you received a link, paste it and select "Read Link", or open the link to pass it to the app.
3. Joiner. Check that the host name in "Received Offer" belongs to the device you intended to pair with, then select "Pair". The screen shows a 6-digit SAS.
4. Host. Select "Approve" only if the number on the approval screen matches the number on the joiner's screen. The peer supplies its own device name, so do not rely on the name alone.
5. Joiner. Select "Check Connection" to receive a one-line greeting that the host returns only to paired peers.

If you remove a paired peer from the host's "Paired Peers" list, that device's "Check Connection" request is rejected. An offer can be used only once. Open a new offer to pair again.

Pairing uses port 4747, and the greeting uses port 4748. The tailnet policy (ACL) must allow connections from the joiner to both ports on the host.

The offer's QR code and link are secret. Show them only to the device you intend to pair. The app's links use a custom scheme (`swiftail-demo://`), so another app that declares the same scheme may receive them. Share offers that include an auth key by QR code.

### Include Auth Key

To let the joiner enter the tailnet without signing in, enable "Include Auth Key" on the host. Enter the ID, secret, and tags of an OAuth client created in the Tailscale admin console (with `auth_keys` write permission and at least one tag), select "Save to Keychain", and open the offer. Each offer gets a single-use key with the same lifetime as the offer. A device that joins using this key becomes a tagged node.

If the joiner is already on the tailnet, it does not use the offer's key.

## Tailnets with tailnet lock enabled

A node that joins with an auth key stays locked until signed. A locked node cannot pair.

1. On the host, open an offer with a lifetime longer than signing will take (15 or 60 minutes).
2. Select "Pair" on the joiner. The node becomes "Connected", but "tailnet lock" shows "Enabled · Awaiting signature". After 60 seconds, the attempt ends with the message "Could not reach the host within 60 seconds. Check that both devices are on the same tailnet. If Tailnet Lock is enabled, retry with the same offer after this device is signed."
3. Copy the `tailscale lock sign …` command from the "Node" section and run it on a signing device in the tailnet.
4. When "tailnet lock" changes to "Enabled · This node is signed", select "Pair" again in "Received Offer". The joiner uses the same offer.

## Logs

Events from each step appear under "Log" and in `events.jsonl` (one event per line with its time, role, event name, and result). The logs omit links, auth keys, OAuth secrets, and sign-in URLs. They omit SAS values unless you enable `--log-confirmation-code` in automation mode.

| Platform | Location |
| --- | --- |
| Mac | `~/Library/Containers/<bundle ID>/Data/Library/Application Support/<bundle ID>/events.jsonl` |
| iPhone | `Library/Application Support/<bundle ID>/events.jsonl` in the app container |

## Automation mode

Use this mode for unattended verification. It requires both the `--automation` launch argument and a loopback control server specified by `--control-url=http://127.0.0.1:<port>`. When enabled, "Automation Mode" appears at the top of the screen. Use the test control server started by the [`tailnet` tool](../../Tools/interop/README.md#tailnet) in `Tools/interop`.

| Argument | What it does |
| --- | --- |
| `--role=host` · `--role=joiner` | Sets the initial role |
| `--auth-key=<key>` | Registers the node with this key at launch. The host also includes it in the offer opened by `--open-offer` |
| `--open-offer` | Opens an offer when the node connects (5-minute lifetime) |
| `--auto-approve` | Approves without showing the approval screen |
| `--write-offer-link` | Writes the open offer's link to `offer-link.txt` next to `events.jsonl` |
| `--log-confirmation-code` | Records the SAS in the logs |

```sh
# Require an auth key on the test server (setAuth), then launch the Mac app as the host.
open -n <built PairingDemo.app> --args --automation --control-url=http://127.0.0.1:<port> \
  --role=host --auth-key=tskey-auth-EXAMPLE --open-offer --auto-approve --write-offer-link --log-confirmation-code
```

Launch the joiner with the same `--automation --control-url=…` arguments and set `--role=joiner`. Open the link in `offer-link.txt`.

After you configure the test server with `setAuth` to require an auth key, it requires the key on every registration request. As a result, relaunching a node with a saved identity on that server ends with the message "The control server rejected registration. Check the tailnet admin policy." To check that the identity and paired peers persist across app relaunches, use a test server started without `setAuth`.
