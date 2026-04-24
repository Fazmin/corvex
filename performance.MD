# corvex-desktop — Performance Improvements

Ordered roughly by return on investment. Each item cites the file path
and line range where the change should land.

## 1. Frontend / UI (biggest user-visible wins)

- [ ] **Virtualize long tables.** Render only visible rows (e.g. `react-window`
      or a simple windowed list). Targets:
  - `ui/src/components/FindingsTable.tsx` L390+ (findings table body)
  - `ui/src/components/ProxyView.tsx` L78, L108 (traffic list)
  - `ui/src/components/HelpView.tsx` L4463-4510 (Nuclei template table)

- [ ] **Batch live Tauri events into `requestAnimationFrame` ticks.**
      Coalesce all findings / exchanges / log lines that arrive inside a
      16 ms window into a single `setState`. Biggest single win during
      fast scans and busy proxy sessions.
  - `ui/src/App.tsx` L285-287 (`setFindings((prev) => [...prev, finding])`)
  - `ui/src/components/ProxyView.tsx` L103-118 (`onProxyExchange`)
  - `ui/src/components/ProxyView.tsx` L1478 (`onScanFinding`)
  - `ui/src/components/ScaView.tsx` L85

- [ ] **Replace `[new, ...prev].slice(0, N)` with a ring buffer.**
      Current pattern is O(N) per event.
  - `ui/src/components/ProxyView.tsx` L108-111
  - `ui/src/App.tsx` L222, L237 (log buffer)

- [ ] **Debounce the search / filter recomputation.** 100–150 ms on the
      `query` state prevents a full filter+sort on every keystroke while
      findings stream in.
  - `ui/src/components/FindingsTable.tsx` L201-234 (`useMemo` filtered)

- [ ] **Memoize expensive per-finding classification.**
      `classify(plugin)` runs for every row on every render; precompute
      once per finding object.
  - `ui/src/components/FindingsTable.tsx` L89-94, L201-234, L258-277

- [ ] **Add `content-visibility: auto` to all long scroll panes.**
      Already used once in `HelpView.tsx` L4460; extend to findings,
      exchanges, recon findings, SCA findings.

- [ ] **Persist filter state once, not on every keystroke.** `useEffect`
      writes to `localStorage` on every state change — debounce these
      writes.
  - `ui/src/components/FindingsTable.tsx` L181-190

## 2. Tauri IPC boundary

- [ ] **Switch large bodies to binary `Channel<Vec<u8>>` instead of
      base64.** Cuts payload size ~33 % and removes a decode step on the
      JS side.
  - `src/proxy_cmd.rs` L117-178 (`exchange_get`)
  - `src/proxy_cmd.rs` L209-220 (`ws_frames_for_exchange`)
  - `src/main.rs` L330-343 (`ws_frame_payload`)

- [ ] **Skip base64/allocations when body is empty or tiny.**
  - `src/proxy_cmd.rs` L143-174

- [ ] **Batch passive findings before emitting.** Under heavy proxy load
      every finding is a separate `emit()` → serialize → IPC roundtrip.
      Buffer N findings or 16 ms worth per `proxy://scan-finding` event.
  - `src/check_bridge.rs` L100-111
  - `src/event_sink.rs` L155-160 (same pattern in scan sink)

- [ ] **Coalesce `open-port` events per host.** One emit per host with
      the full port list is cheaper than N emits per host.
  - `src/commands.rs` L822-844

## 3. Rust backend — caching and parallelism

- [ ] **Cache `nuclei_template_list` results.** Currently re-walks the
      whole bundle and re-parses YAML on every UI call.
  - `src/commands.rs` L1256-1365
  - Invalidate from `nuclei_extras_download` (L1380) and
    `nuclei_extras_remove` (L1498).

- [ ] **Parallelize template loading at startup with `rayon`.** YAML
      parse of hundreds/thousands of templates runs serially today.
  - `src/check_bridge.rs` L27-34

- [ ] **Run `nuclei_extras_download` inside `spawn_blocking`.** The
      gzip + tar extract currently blocks a tokio worker thread.
  - `src/commands.rs` L1380-1493

- [ ] **Avoid re-walking roots in `nuclei_summary`.** Share the cached
      `TemplateStore` from `CheckBridge` instead of building a new one.
  - `src/commands.rs` L1117-1181
  - `src/check_bridge.rs` L27-39 (reuse the same store)

- [ ] **Lazy-load `db::load()` once.** `db_summary` and `scan_start`
      both call `db::load()`; hold the result in a `OnceCell`.
  - `src/commands.rs` L162-181 (db_summary)
  - `src/commands.rs` L390-402 (scan_start)

## 4. SQLite

- [ ] **Replace single-mutex connection with a small pool.** WAL allows
      concurrent readers — use `r2d2_sqlite` or a hand-rolled N-reader
      / 1-writer split.
  - `src/history.rs` L48-62
  - `src/recon_store.rs` L102-118
  - (also `corvex-proxy`'s `ProxyDb`, which this crate drives)

- [ ] **Use prepared-statement caching.** Open statements are rebuilt
      each call; cache per-connection with `Connection::prepare_cached`.
  - `src/history.rs` L104-127 (`list`)
  - `src/recon_store.rs` L217-280 (`list_runs`, `get_run`)
  - `src/recon_store.rs` L283-310 (`findings_for_run`)

- [ ] **Batch recon finding inserts under a transaction.** Each event
      is its own `spawn_blocking` + commit today, which is very chatty
      on a busy run.
  - `src/recon_cmd.rs` L139-216

- [ ] **Pragma tuning for history.sqlite.** `synchronous=NORMAL` is
      already set; also consider `temp_store=MEMORY`, `mmap_size=…`,
      and `cache_size` for faster list/filter queries on long history.
  - `src/history.rs` L58
  - `src/recon_store.rs` L109-113

## 5. Scan orchestration

- [ ] **Surface `max_concurrent_requests` / `max_concurrent_hosts` more
      obviously in the UI.** Defaults are conservative (8 / 4); on
      modern boxes 32–64 requests and 8–16 hosts are fine for many
      targets.
  - `src/commands.rs` L427
  - `src/commands.rs` L767 (probe host concurrency default 8)
  - `src/params.rs` L50-52

- [ ] **Avoid rebuilding `HttpClient`/`TuningFilter`/`EvasionSet` per
      scan when the params are identical.** Cache by hash of inputs.
  - `src/commands.rs` L375-388

- [ ] **Yield inside `expand_ipv4_cidr` / `parse_ipv4_dash_range` for
      large ranges.** Currently builds up to 65 536 entries on a single
      tokio task without yielding.
  - `src/commands.rs` L982-1023, L1077-1112

## 6. Build / bundle

- [ ] **Enable Vite production minification + `esbuild` target bump.**
      Confirm `ui/vite.config.ts` has `build.target: "es2022"` and
      `minify: "esbuild"` (default) so the UI bundle stays small.
  - `ui/vite.config.ts`

- [ ] **Cargo release profile tuning in the workspace root.** If not
      already set, add:
  ```toml
  [profile.release]
  lto = "thin"
  codegen-units = 1
  strip = "symbols"