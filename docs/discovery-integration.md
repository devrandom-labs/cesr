# V1 discovery integration contract

This is the host handoff for the first foundation profile selected in
[the capability matrix](capability-matrix.md). The Rust foundation parses
and judges V1 JSON `qry`/`rpy`; the host owns networking, fetch, cache,
escrow scheduling and durable updates.

1. Bound each incoming frame with `MessageLimits` and call
   `keri_codec::Message::parse`. A `Message::Routed` contains the exact body
   bytes its attachment signs. A parsed SAID or present signature is not an
   acceptance verdict.
2. For a `/logs` query, call `keri::DiscoveryJudge::query`. Resolve the accepted
   historical signer KEL state named by its `-F` seal, if present. The result
   names the authenticated requester, KEL target and first requested
   sequence. The host chooses whether and how to serve it.
3. For a selected in-band reply, call `keri::DiscoveryJudge::reply` with the
   accepted historical signer state at the attachment seal and the previous
   accepted `ReplyVersion` for the **same resource**. A `/ksn/{aid}` notice
   also needs the host's accepted subject KEL state; the judge compares its
   asserted keys, thresholds, witnesses, configuration, delegation and last
   establishment as well as the head coordinate. The KSN report's `p`, `f`
   and `dt` are signed metadata; compare those with the host's accepted event
   and first-seen record if the application relies on their values. The result is
   `Authenticated(version)` or a typed `DiscoveryError` with `disposition()`.
4. In the host's acceptance transaction, atomically persist the reply's
   resource update, accepted body/SAID and returned `ReplyVersion`. Reload
   the marker on restart before judging another reply. Endpoint-role add/cut
   share a resource key `(cid, role, eid)`; a location key is `(eid, scheme)`;
   a KSN key is the subject AID. The host must not key add and cut by their
   distinct route strings, because they update the same role assignment.
5. A missing accepted signer or subject state is an awaiting evidence result:
   retain the exact framed message and re-drive it once the KEL evidence is
   accepted. A contradictory supplied state, wrong signer, invalid signature
   or stale version is terminal for that candidate. Escrow storage, timers,
   retries and network fetch remain host decisions.

`/oobi/witness` produces `UntrustedHint` even if its JSON body has a valid
SAID. An OOBI URL or returned data cannot create trusted endpoint or KEL
state by itself. The host may fetch from the URL, then feed returned KEL,
receipt and in-band reply material through their ordinary verification and
acceptance paths. This contract does not imply Signify/KERIA compatibility;
the selected Selo client/agent route is tracked by A23.

The V1 grammar is `qry: v,t,d,dt,r,rr,q` and `rpy: v,t,d,dt,r,a`, with no
top-level sender `i`. `keri_codec::RoutedBody::write_query` and
`write_reply` produce this body form and compute its SAID. The host attaches
authenticators and frames the result according to the V1 text CESR profile.
V2, native bodies, CBOR/MGPK and raw mixed binary transport are separate
profiles; their typed boundaries reject them here.
