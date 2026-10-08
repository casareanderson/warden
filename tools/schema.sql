CREATE TABLE events(
  id integer primary key, ts text, source text, ip text,
  kind text, detail text, score integer);
CREATE TABLE bans(
  id integer primary key, ts text, ip text, score integer,
  reasons text, state text, expires text, note text);
CREATE TABLE watermarks(source text primary key, pos text);
CREATE TABLE runs(
  id integer primary key, ts text, source text, lines integer,
  parsed integer, note text);
CREATE INDEX ev_ip on events(ip);
CREATE INDEX ev_ts on events(ts);
CREATE TABLE seen(h text primary key, ts text);
CREATE TABLE net_hosts(
  mac text primary key, ip text, hostname text, vendor text,
  first_seen text, last_seen text, approved integer default 0, note text);
CREATE TABLE net_ports(
  mac text, port integer, proto text, service text,
  first_seen text, last_seen text, primary key(mac, port, proto));
CREATE TABLE net_alerts(
  id integer primary key, ts text, kind text, mac text, ip text,
  detail text, notified integer default 0);
CREATE TABLE net_runs(
  id integer primary key, ts text, network text, hosts integer, note text);
CREATE INDEX nh_ip on net_hosts(ip);
CREATE INDEX na_ts on net_alerts(ts);
CREATE TABLE net_host_ips(
  mac text, ip text, first_seen text, last_seen text, primary key(mac, ip));
CREATE TABLE alert_sent(
  h text primary key, ts text, kind text, summary text);
CREATE TABLE alert_suppressed(
  id integer primary key, ts text, kind text, detail text, reason text);
CREATE TABLE edge_events(
        id integer primary key, ts text, ray text unique, ip text, cc text, action text,
        source text, host text, path text, ua text, rule text);
CREATE INDEX ee_ts on edge_events(ts);
CREATE TABLE surface_snap(id integer primary key, ts text, data text);
CREATE TABLE edge_bans(
        id integer primary key, target text, reason text, score integer, status text,
        message_id text, created text, decided text, expires text, note text);
CREATE INDEX eb_target on edge_bans(target);
CREATE TABLE vuln_targets(
        target text primary key, kind text, name text, node text, vmid integer, os text,
        last_scan text, status text, note text, pkgs integer, upgradable integer,
        reboot_required integer, kernel text, newest_kernel text, patchable integer,
        n_total integer, n_fixable integer, n_crit_fix integer, n_high_fix integer, n_kev integer);
CREATE TABLE vulns(
        target text, vid text, pkg text, installed text, fixed text, severity text, title text,
        kev integer, status text, image text, primary key(target, vid, pkg, image));
CREATE INDEX vu_vid on vulns(vid);
CREATE TABLE patch_jobs(
        id integer primary key, target text, name text, status text, requested_by text, requested text,
        plan text, n_pkgs integer, n_remove integer, message_id text, decided text, snapshot text,
        result text, before_fix integer, after_fix integer, reboot text, finished text, timing text, run_after text, timing_why text);
CREATE TABLE integ_base(target text, kind text, item text, value text,
        primary key(target, kind, item));
CREATE TABLE integ_find(id integer primary key, ts text, target text, kind text, item text,
        old text, new text, change text, status text, message_id text, note text);
CREATE INDEX if_status on integ_find(status);
CREATE TABLE integ_runs(target text primary key, ts text, deep_ts text, facts integer,
        status text, note text);
CREATE TABLE ids_alerts(
        id integer primary key, ts text, sid integer, signature text, severity integer, category text,
        src text, sport integer, dst text, dport integer, proto text, app text, cc text, community_id text,
        notified integer default 0);
CREATE INDEX ia_ts on ids_alerts(ts);
CREATE TABLE intel_hits(
        id integer primary key, ts text, device text, device_name text, kind text, indicator text,
        feed text, detail text, notified integer default 0);
CREATE INDEX ih_ts on intel_hits(ts);
CREATE TABLE harden(target text primary key, name text, ts text, idx integer, tests integer,
        warnings text, suggestions text, status text, note text, prev_idx integer);
CREATE TABLE img_advice(host text, container text, image text, managed text, workdir text,
        service text, newer_pulled integer, image_date text, kev integer, crit_fix integer, fixable integer,
        action text, why text, ts text, primary key(host, container));
