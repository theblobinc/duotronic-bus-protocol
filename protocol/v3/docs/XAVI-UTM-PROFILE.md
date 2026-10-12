# Xavi-UTM Profile

This profile maps DBP v3 to Xavi-UTM's federated operational needs without making DBP itself a UTM policy engine.

Recommended streams:

1. **Emergency/control** — bounded canonical emergency and safety intents.
2. **Command transactions** — idempotent operator/autonomy proposals and results.
3. **Telemetry** — aircraft/drone/sensor state, deadlines and replaceable updates.
4. **Human decisions** — proposal/decision records bound to authenticated user/session and Witness evidence.
5. **Text/PTT signalling** — reliable low-bandwidth operator coordination.
6. **Voice** — latency-sensitive protected media fragments.
7. **Video** — deadline/replaceable protected media fragments.
8. **Presence/group** — crew/channel membership and session epochs.
9. **Map/object** — GIS, mission plan, imagery and evidence object transfer.
10. **Federation/evidence** — authority snapshots, custody receipts and server-to-server evidence references.

Degradation preference is emergency/control > ACK/receipt > command/telemetry > text > voice > video > bulk. Video should lose frame rate/resolution before voice or control are starved. At severe degradation the profile can reduce to protected store-and-forward text/control.

A human decision is not proven merely because a browser/API POST succeeded. It should bind transaction identity, authenticated principal/session, proposal digest, decision, time evidence and staged execution/outcome receipts.
