# Teaching a Ruckus AP to Sniff: The M0 Dogfight

*A field log from building a multi-AP 802.11 capture orchestrator — how we went from
an empty directory to 120 verified frames of over-the-air traffic, and every wall we
hit along the way.*

---

## The mission

We're building a local web tool that turns a rack of Ruckus APs into a coordinated
packet-capture array: pick a venue, pin each radio to a channel, and stream monitor-mode
802.11 into pcaps on a capture host — CWAP-grade, with radiotap-style radio metadata,
other-BSS visibility, the works.

The whole project rests on one assumption in milestone zero (**M0**): *that a Ruckus AP
can actually be driven, over SSH, into a useful monitor capture.* Everything downstream —
the adapters, the state machine, the artifact pipeline — is wasted effort if that turns
out to be false or unusable. So before writing a line of application code, we went to
find out. We had exactly one lab AP on the LAN and a password that rotates.

Spoiler: it works. But the path there was not a straight line.

---

## Act I — Getting in the door

First surprise arrived immediately. SSH to the AP with `admin` and the password: **auth
failure.** Same for `super`, `root`. Yet the operator swore the credentials were right.

The clue was in how paramiko's `auth_none()` behaved — it returned an empty list, which
in SSH-speak means *"you're authenticated, come on in."* The AP accepts the SSH transport
with the **`none`** method — no password at the SSH layer at all. The real gate is a
*second*, application-level login presented over the shell channel:

```
Please login:  admin
password :     ••••••••
rkscli:
```

Note the space before the colon in `password :` — a detail that bit us once when our
prompt-matcher looked for `password:` and instead fed the password in as a *command*,
earning a cheerful `Login incorrect`. Match on substrings, not exact strings. Lesson one
of embedded gear: it will not behave like OpenSSH, and it will not tell you why.

Once past it, we landed in `rkscli:` on a **Ruckus R510**, firmware `6.2.4.103.262`, two
radios: `wifi0` (2.4 GHz) and `wifi1` (5 GHz).

---

## Act II — Reading the manual that doesn't exist

`rkscli` has hundreds of commands and no obvious "capture packets" verb. We spelunked the
help groups (`help debuggroup`, `help radiogroup`) and used the CLI's own last-resort text
search (`help capture`, `help tcpdump`, `help monitor`, …). `tcpdump`? *"Sorry, no match."*
But `help capture` paid out:

```
set capture <interface> {idle | [stream|local][-no[b][c][m][d][p]]
                          [restart] [showLDPC] [mac_addr] [limited_IP]}
```

There it was. And a quiet architectural bombshell alongside it: `get/set rpcapd bpf` and
a `stream` mode that takes a *"limited access IP."* The AP doesn't hand you raw pcap over
SSH stdout like our design assumed — it runs **rpcapd**, the remote-pcap daemon, and
streams frames over the rpcap protocol to a capture host. That's a better mechanism (live
counters for free), but it meant our capture writer would attach via `rpcap://`, not read
a byte stream. First design correction, logged.

The filter flags decoded nicely too: `-nob/-noc/-nom/-nod` drop beacon/control/mgmt/data,
`-nop` disables promiscuous. Which means the **default is promiscuous, all frame types** —
exactly the whole-channel visibility CWAP wants, for free.

---

## Act III — "That logic is silly"

We tried to read the capture state and hit a wall:

```
get capture wifi1 state  ->  Err:Interface-Inactive, wifi1 must have an active wlan
```

Every WLAN on the AP was `down`. No radio was up. And you can't capture on a radio that
isn't on-channel. The operator's reaction was the correct one:

> *"So I can't have an AP monitor a channel until a WLAN exists, which I would then need
> to interrupt?"*

Fair. It *sounds* absurd. So rather than shrug, we went looking for a true WLAN-less
monitor mode: `help spectrum` (nothing), `help sensor` (only orientation/temperature
*hardware* sensors), the scan machinery (`scand`, `chanbkgndscan`, `rescan` — all
off-channel *hopping*, tied to an operating radio). Conclusion: **there is no monitor-mode-
without-a-BSS on a Ruckus AP-mode radio.** The PHY is brought on-channel by having a BSS.

But "silly" dissolves once you separate two things: *a BSS being enabled* is not the same
as *serving clients.* On a **dedicated capture AP** — which is exactly the plan — you
deploy a throwaway SSID that nobody ever associates to. It's inert scaffolding that keeps
the radio parked on a channel. Promiscuous capture still sees the entire channel; your own
BSS is the only self-noise, and `-nob` filters its beacons out. Nothing gets "interrupted"
because there was never anything to interrupt.

The operator pushed a dummy SSID to the venue from Ruckus One — `capture_the_flag` — and
seconds later both radios came up: `wifi0` on channel 1, `wifi1` on channel 36, and
`get capture` finally returned `idle` instead of an error. Green light.

---

## Act IV — The rpcap dogfight

This is where M0 tried to defeat us, and where the trial-and-error got real.

**Handicap round.** The capture host had no `dumpcap`, no `tshark` — only `tcpdump`, and
we were a non-root user. So: no attaching a real rpcap client, no binding FTP/TFTP's
privileged ports to pull a file, and `tcpdump` itself refused (`Operation not permitted`).
We would have to speak the **rpcap wire protocol by hand**, in Python, from scratch.

**Attempt 1.** Connect to `rpcapd` on TCP 2002. Null auth — *accepted.* Open interface
`wifi1` — *accepted*, and the reply carried the prize: **link-type 192 = DLT_PPI.** That
single number answered the "do we get radio metadata?" question: yes, wrapped in PPI
(Per-Packet Information: rate, channel, RSSI). Then `STARTCAP` … **hung.** No reply.

**The misdirections.** What followed was a run of plausible wrong theories:

- *"It's active mode — the AP dials us."* The CLI printed `Connection established` when we
  started a stream, which sure sounds like an outbound connection. We stood up a listener
  on port 2002 and waited. The AP never called. We checked the socket table with `ss` while
  triggering a stream — the only connections to the AP were *our own SSH sessions.*
  `Connection established` was rpcapd talking about its own internal readiness, not a TCP
  dial-out. Theory dead.
- *"The 5 GHz channel is the problem."* Our first captures targeted `wifi1` on channel 36 —
  a dead-quiet channel with no neighbors, where even the AP's own transmitted frames aren't
  looped back to the monitor. Zero packets looked like a bug but was partly just *silence.*
  We moved to `wifi0` (2.4 GHz, channel 1) — a noisy channel full of neighbors.
- *"Maybe the data comes back on a second connection."* It does: with the `SERVEROPEN` flag,
  rpcapd connects *back* to a port we advertise. That handshake worked — `data conn from
  ('10.0.71.128', …)` — but the socket sat there **silent.** Data channel open, nothing
  flowing.

Silent data channel + no `STARTCAP` reply, even on a channel we *knew* was busy. Something
was wrong with the request itself.

**The breakthrough.** We'd been sending a bare `rpcap_startcapreq` (12 bytes) — but the
rpcap protocol expects a **BPF filter block appended** to it. Add it, and suddenly the
server *replies* … with an error:

```
startcap ERROR 12: The filter contains bogus instructions
```

Progress! A reply is a reply. An *empty* filter program is invalid; rpcapd wants a real
accept-all BPF instruction — `RET 0xffffffff`. We sent one. The `STARTCAP` reply came back
clean (`0x84`), the data channel woke up … and immediately spat messages we skipped as
"non-packet" because their type byte was **`0x07`**, not the `0x87` (`0x80|7`) our reader
assumed for packet messages. One-line fix to accept `0x07`, and:

```
[done] wrote 120 pkts, 41269 bytes -> cap_wifi0.pcap
```

Three separate protocol quirks — missing filter block, empty-program rejection, and a
nonstandard packet-message tag — stacked on top of each other, each one masking the next.
That's why it felt like a wall instead of a bug.

---

## Act V — The payoff

We decoded the 120 frames with scapy. The numbers are the whole point of M0:

- **PPI radio headers on 100% of frames** — every frame carries rate/channel/RSSI metadata.
- **All three frame classes:** 85 management, 25 control, 10 data. Control frames (CTS/ACK)
  only show up for a true promiscuous, on-channel monitor — so this is the real thing, not
  an own-BSS-only view.
- **Other-BSS visibility, unambiguously:** 26 distinct transmitters, and neighbor SSIDs
  bleeding in from all around — `Travis`, `legacycoffee`, `36hoursinGuyton`, a scatter of
  `Recover.Me-*` APs, even an HP printer's `DIRECT-*` — right next to our own
  `capture_the_flag`.

That's a genuine over-the-air capture of an entire channel, pulled off a production-class
AP with nothing but SSH and a hand-rolled rpcap client. M0's core assumption holds.

---

## What we actually learned

1. **The controller API is the small, stable surface; the AP CLI is the powerful one.**
   Ruckus One's cloud API can start a capture too, but it takes no channel, width, duration,
   or ring-buffer — it captures on whatever the radio is already serving. The rich control
   lives in `rkscli set capture`. That split is the reason the project runs two tracks.
2. **Radio-up requires a BSS, and that's fine.** Dedicated capture APs run an inert throwaway
   SSID as scaffolding. The one honest caveat: the AP *does* transmit on-channel, so it's not
   a 100%-passive sensor. Negligible for troubleshooting; filterable; worth stating plainly.
3. **rpcapd is the transport.** For the product, the capture writer should first try stock
   `dumpcap -i rpcap://<ap>/wifiN` (libpcap speaks rpcap natively and would've spared us this
   whole act). Our hand-rolled reader is the documented fallback — and, usefully, it *proves*
   the exact protocol dialect this firmware speaks.
4. **Hardware shapes the fleet.** The R510 is 2.4 + 5 only — no 6 GHz, and a single 5 GHz
   radio, so one R510 can't watch two 5 GHz channels at once. Two-channels-per-AP works, but
   as 2.4 + 5. Dual-5 GHz coverage needs tri-radio hardware.

The scratchpad tools that got us here — `apcli.py` (the rkscli driver), `rpcap_client.py`
(the working rpcap reader), `decode.py` — aren't throwaway. They're the seeds of the real
`engine/ssh.py` and `engine/writer.py`. M0 didn't just de-risk the build; it wrote its first
two modules in disguise.

*Next stop: the R1 native-capture API and channel pinning — or scaffolding the app around a
capture mechanism we now know, for a fact, works.*
