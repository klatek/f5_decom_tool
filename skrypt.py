#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import io
import os
import re
import sys
import subprocess
from collections import defaultdict, deque

# F5 BIG-IP decommission inventory and safe-delete helper
# Python 2.7.5 compatible
# Version 17:
# - Adds external pool dependency scan across LTM, APM and AFM modules.
# - Pools referenced by APM/AFM or non-selected LTM objects are protected from delete commands.
# - Orphaned pool detection now means no pool reference anywhere in scanned ltm/apm/afm blocks, excluding the pool definition itself.
# - Keeps full defaults-from dependency graph behavior from ver15.
# - Keeps fast tokenized lookup maps, no global orphaned data-group cleanup, DNS deduplication, dig +short -x, sleep 1.5.
# - Script prints commands only. It does not execute delete commands.

DIG_COMMAND = "dig"
DIG_OPTIONS = "+short -x"
COMMAND_DELAY = "sleep 1.5"
COMMON_PREFIX = "/Common/"
TOKEN_RE = re.compile(r"/[-A-Za-z0-9_./]+|[-A-Za-z0-9_.]+")
TOP_BLOCK_RE = re.compile(r"^(ltm|apm|afm)\s+(.+?)\s*\{\s*$", re.MULTILINE)

BUILT_IN_MONITORS = set(["tcp", "tcp_half_open", "tcp-half-open", "http", "https", "icmp", "gateway_icmp", "gateway-icmp", "udp", "smtp", "ftp", "sip", "dns", "ldap", "radius", "mysql", "postgresql", "oracle", "mssql", "nntp", "pop3", "imap", "wmi", "real_server"])
BUILT_IN_PERSISTENCE = set(["cookie", "source_addr", "source-addr", "ssl", "dest_addr", "dest-addr", "hash", "universal", "msrdp", "sip", "carp", "uie"])
BUILT_IN_TCP_PROFILES = set(["tcp", "tcp-lan-optimized", "tcp-wan-optimized", "tcp-mobile-optimized", "f5-tcp-progressive"])
BUILT_IN_ONECONNECT_PROFILES = set(["oneconnect"])
BUILT_IN_CLIENT_SSL_PROFILES = set(["clientssl", "clientssl-insecure-compatible"])
BUILT_IN_SERVER_SSL_PROFILES = set(["serverssl", "serverssl-insecure-compatible"])
GRAPH_PROFILE_TYPES = set(["persistence profile", "client ssl profile", "server ssl profile", "tcp profile", "one-connect profile", "pool monitor"])


def usage():
    print("Usage: {0} <f5_config_file>".format(sys.argv[0]))
    print("Example: python {0} bigip.conf".format(sys.argv[0]))

if len(sys.argv) != 2:
    usage()
    sys.exit(1)

F5_CONFIG_FILE = sys.argv[1]
if not os.path.isfile(F5_CONFIG_FILE):
    print("Error: File '{0}' does not exist".format(F5_CONFIG_FILE))
    sys.exit(1)

with io.open(F5_CONFIG_FILE, "r", encoding="utf-8", errors="ignore") as f:
    config = f.read()

print("\nPaste Virtual Servers, one per line.")
print("Use the exact virtual server name from the config, for example:")
print("/Common/xidsadmin.swacorp.com-https")
print("Press ENTER on an empty line when finished.\n")

requested_list = []
requested_set = set()
while True:
    try:
        line = raw_input().strip()
    except EOFError:
        break
    if not line:
        break
    if line not in requested_set:
        requested_list.append(line)
        requested_set.add(line)

if not requested_set:
    print("No virtual servers supplied.")
    sys.exit(0)


def unique_list(items):
    seen = set(); out = []
    for item in items:
        if item and item not in seen:
            out.append(item); seen.add(item)
    return out


def strip_common(name):
    if not name or name == "-": return name
    if name.startswith(COMMON_PREFIX): return name[len(COMMON_PREFIX):]
    return name


def normalize_builtin_name(name):
    n = strip_common(name)
    if not n: return n
    return n.replace("-", "_")


def common_candidates(name):
    if not name or name == "-": return []
    if name.startswith(COMMON_PREFIX): return unique_list([name, strip_common(name)])
    return unique_list([name, COMMON_PREFIX + name])


def canonical_name(name, registry):
    if not name or name == "-": return "-"
    for c in common_candidates(name):
        if c in registry: return c
    return name


def exists_in_registry(name, registry):
    if not name or name == "-": return False
    for c in common_candidates(name):
        if c in registry: return True
    return False


def is_builtin(name, builtin_set):
    if not name or name == "-": return False
    return strip_common(name) in builtin_set or normalize_builtin_name(name) in builtin_set


def objkey(typ, name): return typ + "|" + name

def split_objkey(key):
    p = key.split("|", 1)
    return p[0], p[1]


def find_blocks(obj_type):
    pattern = re.compile(r"ltm\s+{0}\s+(\S+)\s*\{{".format(obj_type), re.MULTILINE)
    results = []
    for m in pattern.finditer(config):
        name = m.group(1); pos = m.end(); depth = 1
        while pos < len(config) and depth > 0:
            ch = config[pos]
            if ch == "{": depth += 1
            elif ch == "}": depth -= 1
            pos += 1
        results.append((name, config[m.end():pos - 1]))
    return results


def find_monitor_blocks():
    pattern = re.compile(r"ltm\s+monitor\s+(\S+)\s+(\S+)\s*\{", re.MULTILINE)
    results = []
    for m in pattern.finditer(config):
        mtype = m.group(1); name = m.group(2); pos = m.end(); depth = 1
        while pos < len(config) and depth > 0:
            ch = config[pos]
            if ch == "{": depth += 1
            elif ch == "}": depth -= 1
            pos += 1
        results.append((mtype, name, config[m.end():pos - 1]))
    return results


def find_persistence_blocks():
    pattern = re.compile(r"ltm\s+persistence\s+(\S+)\s+(\S+)\s*\{", re.MULTILINE)
    results = []
    for m in pattern.finditer(config):
        ptype = m.group(1); name = m.group(2); pos = m.end(); depth = 1
        while pos < len(config) and depth > 0:
            ch = config[pos]
            if ch == "{": depth += 1
            elif ch == "}": depth -= 1
            pos += 1
        results.append((ptype, name, config[m.end():pos - 1]))
    return results


def find_module_blocks(modules):
    results = []
    for m in TOP_BLOCK_RE.finditer(config):
        module = m.group(1)
        if module not in modules: continue
        header_tail = m.group(2).strip()
        header = module + " " + header_tail
        pos = m.end(); depth = 1
        while pos < len(config) and depth > 0:
            ch = config[pos]
            if ch == "{": depth += 1
            elif ch == "}": depth -= 1
            pos += 1
        results.append((module, header, config[m.start():pos]))
    return results


def top_level_value(body, keyword):
    depth = 0
    for line in body.splitlines():
        s = line.strip()
        if depth == 0:
            m = re.match(r"^{0}\s+(\S+)".format(re.escape(keyword)), s)
            if m: return m.group(1)
        depth += line.count("{") - line.count("}")
        if depth < 0: depth = 0
    return "-"


def top_level_section_body(body, section_name):
    lines = body.splitlines(); depth = 0; start = None; section_depth = None
    for i, line in enumerate(lines):
        s = line.strip()
        if depth == 0 and re.match(r"^{0}\s*\{{".format(re.escape(section_name)), s):
            start = i; section_depth = depth + line.count("{") - line.count("}"); break
        depth += line.count("{") - line.count("}")
        if depth < 0: depth = 0
    if start is None: return ""
    collected = []; depth = section_depth
    for line in lines[start + 1:]:
        old = depth; depth += line.count("{") - line.count("}")
        if old == 1 and depth <= 0 and line.strip() == "}": break
        collected.append(line)
    return "\n".join(collected)


def first_level_section_entries(body, section_name):
    section = top_level_section_body(body, section_name)
    entries = []; depth = 0
    skip = set(["context", "default", "replace-all-with", "requires", "controls", "description", "partition", "status", "strategy", "rules", "actions", "conditions", "operands", "values", "case-sensitive", "ordinal", "legacy"])
    for line in section.splitlines():
        s = line.strip()
        if not s or s in ("{", "}"):
            depth += line.count("{") - line.count("}")
            if depth < 0: depth = 0
            continue
        if depth == 0:
            token = s.split()[0]
            if token.endswith("{"): token = token[:-1]
            if token not in skip and not token.startswith("#"):
                entries.append(token)
        depth += line.count("{") - line.count("}")
        if depth < 0: depth = 0
    return unique_list(entries)


def build_alias_map(registry):
    alias = {}
    keys = registry.keys() if hasattr(registry, "keys") else registry
    for name in keys:
        for c in common_candidates(name): alias[c] = name
    return alias


def extract_named_refs_fast(text, alias_map):
    found = []; seen = set()
    if not text or not alias_map: return found
    for token in TOKEN_RE.findall(text):
        if token in alias_map:
            obj = alias_map[token]
            if obj not in seen:
                found.append(obj); seen.add(obj)
    return found


def is_ipv4(value):
    parts = value.split(".")
    if len(parts) != 4: return False
    for p in parts:
        if not p.isdigit(): return False
        n = int(p)
        if n < 0 or n > 255: return False
    return True


def extract_destination(body):
    raw = top_level_value(body, "destination")
    if raw == "-": return "-", "-"
    host = strip_common(raw)
    if ":" in host and host.count(":") == 1: host = host.rsplit(":", 1)[0]
    if "%" in host: host = host.split("%", 1)[0]
    if is_ipv4(host): return raw, host
    return raw, "-"


def vs_to_fqdn(vs_name):
    fqdn = strip_common(vs_name)
    for suffix in ["-http-redirect", "-https-redirect", "-https", "-http"]:
        if fqdn.endswith(suffix): return fqdn[:-len(suffix)]
    m = re.match(r"^(.+\.\S+)-(\d+)$", fqdn)
    if m: return m.group(1)
    return fqdn


def extract_cert_key(body):
    cert = "-"; key = "-"
    m = re.search(r"^\s*cert\s+(\S+)", body, re.MULTILINE)
    if m: cert = m.group(1)
    m = re.search(r"^\s*key\s+(\S+)", body, re.MULTILINE)
    if m: key = m.group(1)
    if cert == "-":
        m = re.search(r"cert-key-chain\s*\{.*?^\s*cert\s+(\S+)", body, re.DOTALL | re.MULTILINE)
        if m: cert = m.group(1)
    if key == "-":
        m = re.search(r"cert-key-chain\s*\{.*?^\s*key\s+(\S+)", body, re.DOTALL | re.MULTILINE)
        if m: key = m.group(1)
    return cert, key


def extract_snat_pool(body):
    section = top_level_section_body(body, "source-address-translation")
    for line in section.splitlines():
        m = re.match(r"^\s*pool\s+(\S+)", line.strip())
        if m: return canonical_name(m.group(1), snatpool_defs)
    return "-"


def extract_pool_nodes(pool_body):
    section = top_level_section_body(pool_body, "members")
    nodes = []
    if section:
        depth = 0
        for line in section.splitlines():
            s = line.strip()
            if depth == 0 and s and s not in ("{", "}"):
                token = s.split()[0]
                if token.endswith("{"): token = token[:-1]
                if ":" in token: nodes.append(canonical_name(token.rsplit(":", 1)[0], node_defs))
            depth += line.count("{") - line.count("}")
            if depth < 0: depth = 0
    else:
        for n in re.findall(r"(/Common/[^\s{}:]+|[^\s{}:]+):[^\s{}]+", pool_body):
            nodes.append(canonical_name(n, node_defs))
    return unique_list(nodes)


def extract_pool_monitors(pool_body):
    m = re.search(r"^\s*monitor\s+(.+)$", pool_body, re.MULTILINE)
    if not m: return [], []
    start = m.start(); end = pool_body.find("\n", start)
    if end == -1: end = len(pool_body)
    text = pool_body[start:end]
    if "{" in text:
        bs = pool_body.find("{", start); pos = bs + 1; depth = 1
        while pos < len(pool_body) and depth > 0:
            if pool_body[pos] == "{": depth += 1
            elif pool_body[pos] == "}": depth -= 1
            pos += 1
        text = pool_body[start:pos]
    custom = []; builtin = []; ignore = set(["monitor", "min", "of", "and", "none", "default", "all"])
    for mon in re.findall(r"(/Common/[^\s{}]+|[^\s{}]+)", text):
        if mon in ignore: continue
        if exists_in_registry(mon, monitors): custom.append(canonical_name(mon, monitors))
        elif is_builtin(mon, BUILT_IN_MONITORS): builtin.append(mon)
        elif mon.startswith(COMMON_PREFIX): custom.append(mon)
    return unique_list(custom), unique_list(builtin)


def extract_persistence_profiles_from_virtual(body):
    profiles = []
    section = top_level_section_body(body, "persist")
    if section: profiles.extend(re.findall(r"(/Common/[^\s{}]+|[^\s{}]+)\s*\{", section))
    fallback = top_level_value(body, "fallback-persistence")
    if fallback != "-": profiles.append(fallback)
    custom = []; builtin = []
    for p in profiles:
        if exists_in_registry(p, persistence_profiles): custom.append(canonical_name(p, persistence_profiles))
        elif is_builtin(p, BUILT_IN_PERSISTENCE): builtin.append(p)
        else: custom.append(p)
    return unique_list(custom), unique_list(builtin)


def extract_profile_entries_from_virtual(body):
    section = top_level_section_body(body, "profiles")
    entries = []; depth = 0
    for line in section.splitlines():
        s = line.strip()
        if depth == 0 and s and s not in ("{", "}"):
            token = s.split()[0]
            if token.endswith("{"): token = token[:-1]
            if token not in ("context", "default", "replace-all-with"): entries.append(token)
        depth += line.count("{") - line.count("}")
        if depth < 0: depth = 0
    return unique_list(entries)


def classify_profiles(entries):
    client = []; server = []; tcp = []; onec = []; builtin = []; unknown = []
    for p in entries:
        if exists_in_registry(p, client_profiles): client.append(canonical_name(p, client_profiles))
        elif exists_in_registry(p, server_profiles): server.append(canonical_name(p, server_profiles))
        elif exists_in_registry(p, tcp_profiles): tcp.append(canonical_name(p, tcp_profiles))
        elif exists_in_registry(p, oneconnect_profiles): onec.append(canonical_name(p, oneconnect_profiles))
        elif is_builtin(p, BUILT_IN_TCP_PROFILES) or is_builtin(p, BUILT_IN_ONECONNECT_PROFILES) or is_builtin(p, BUILT_IN_CLIENT_SSL_PROFILES) or is_builtin(p, BUILT_IN_SERVER_SSL_PROFILES): builtin.append(p)
        else: unknown.append(p)
    return unique_list(client), unique_list(server), unique_list(tcp), unique_list(onec), unique_list(builtin), unique_list(unknown)


def get_monitor_type(name): return monitors.get(canonical_name(name, monitors), {}).get("type", "unknown")
def get_monitor_cert(name): return monitors.get(canonical_name(name, monitors), {}).get("cert", "-")
def get_monitor_key(name): return monitors.get(canonical_name(name, monitors), {}).get("key", "-")
def get_persistence_type(name): return persistence_profiles.get(canonical_name(name, persistence_profiles), {}).get("type", "unknown")
def get_data_group_type(name): return data_groups.get(canonical_name(name, data_groups), "unknown")


def add_ref(refs, typ, name, vs):
    if name and name != "-": refs[typ][name].add(vs)


def add_command(groups, typ, name, cmd):
    if name and name != "-": groups[typ][name] = cmd


def get_external_vip_refs(typ, name):
    return sorted([v for v in object_refs.get(typ, {}).get(name, set()) if v not in requested_set])


def is_safe_vs_scope(typ, name):
    if typ == "virtual server": return True
    return len(get_external_vip_refs(typ, name)) == 0


def dig_short_lookup(ip):
    if not ip or ip == "-": return []
    cmd = [DIG_COMMAND]
    for opt in DIG_OPTIONS.split():
        if opt: cmd.append(opt)
    cmd.append(ip)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if not stdout: return []
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
    except Exception as e:
        return ["lookup_failed: {0}".format(e)]

# Registries
client_profiles = {}
for name, body in find_blocks("profile client-ssl"):
    cert, key = extract_cert_key(body)
    client_profiles[name] = {"cert": cert, "key": key, "defaults_from": top_level_value(body, "defaults-from")}
server_profiles = {}
for name, body in find_blocks("profile server-ssl"):
    cert, key = extract_cert_key(body)
    server_profiles[name] = {"cert": cert, "key": key, "defaults_from": top_level_value(body, "defaults-from")}
tcp_profiles = {}
for name, body in find_blocks("profile tcp"):
    tcp_profiles[name] = {"defaults_from": top_level_value(body, "defaults-from")}
oneconnect_profiles = {}
for name, body in find_blocks("profile one-connect"):
    oneconnect_profiles[name] = {"defaults_from": top_level_value(body, "defaults-from")}
snatpool_defs = set([name for name, body in find_blocks("snatpool")])
node_defs = set([name for name, body in find_blocks("node")])
persistence_profiles = {}
for ptype, name, body in find_persistence_blocks():
    persistence_profiles[name] = {"type": ptype, "defaults_from": top_level_value(body, "defaults-from")}
monitors = {}
for mtype, name, body in find_monitor_blocks():
    cert, key = extract_cert_key(body)
    monitors[name] = {"type": mtype, "cert": cert, "key": key, "defaults_from": top_level_value(body, "defaults-from")}
data_groups = {}
for name, body in find_blocks("data-group internal"):
    data_groups[name] = "internal"
for name, body in find_blocks("data-group external"):
    data_groups[name] = "external"
rule_defs = dict(find_blocks("rule"))
policy_defs = dict(find_blocks("policy"))

# defaults-from graph
profile_registries = {"client ssl profile": client_profiles, "server ssl profile": server_profiles, "tcp profile": tcp_profiles, "one-connect profile": oneconnect_profiles, "persistence profile": persistence_profiles, "pool monitor": monitors}
defaults_parent = defaultdict(dict)
defaults_children = defaultdict(lambda: defaultdict(set))
for typ, registry in profile_registries.items():
    for child, data in registry.items():
        parent = canonical_name(data.get("defaults_from", "-"), registry)
        if parent and parent != "-" and exists_in_registry(parent, registry):
            defaults_parent[typ][child] = parent
            defaults_children[typ][parent].add(child)

pools = {}
for name, body in find_blocks("pool"):
    custom_monitors, builtin_monitors = extract_pool_monitors(body)
    pools[name] = {"nodes": extract_pool_nodes(body), "monitors": custom_monitors, "builtin_monitors": builtin_monitors}
pool_alias_map = build_alias_map(pools)
data_group_alias_map = build_alias_map(data_groups)

# External pool reference scan across ltm/apm/afm.
# This is the main ver16 safety check.
pool_module_refs = defaultdict(list)
for module, header, block_text in find_module_blocks(set(["ltm", "apm", "afm"])):
    for pool_name in extract_named_refs_fast(block_text, pool_alias_map):
        # Do not count the pool definition as a usage of itself.
        if header == "ltm pool {0}".format(pool_name):
            continue
        pool_module_refs[pool_name].append(header)
for p in pool_module_refs.keys():
    pool_module_refs[p] = unique_list(pool_module_refs[p])

virtuals = dict(find_blocks("virtual"))

# Inventory all virtual servers and VS-based references
all_virtual_inventory = {}
object_refs = defaultdict(lambda: defaultdict(set))
for vs_name, body in virtuals.items():
    raw_pool = top_level_value(body, "pool")
    top_pool = canonical_name(raw_pool, pools)
    destination_raw, destination_ip = extract_destination(body)
    snat = extract_snat_pool(body)
    raw_policies = first_level_section_entries(body, "policies")
    policies = [canonical_name(p, policy_defs) for p in raw_policies]
    policy_map = [(raw_policies[i], policies[i], exists_in_registry(policies[i], policy_defs)) for i in range(len(policies))]
    raw_irules = first_level_section_entries(body, "rules")
    irules = [canonical_name(r, rule_defs) for r in raw_irules]
    irule_map = [(raw_irules[i], irules[i], exists_in_registry(irules[i], rule_defs)) for i in range(len(irules))]
    entries = extract_profile_entries_from_virtual(body)
    client_ssl_profiles, server_ssl_profiles, tcp_profile_list, one_connect_profiles_list, builtin_profiles, unknown_profiles = classify_profiles(entries)
    persistence, builtin_persistence = extract_persistence_profiles_from_virtual(body)

    pools_from_irules = []; pools_from_policies = []; pool_source_lines = []
    for raw, irule, exists_flag in irule_map:
        body_text = rule_defs.get(canonical_name(irule, rule_defs), "")
        found = extract_named_refs_fast(body_text, pool_alias_map)
        pools_from_irules.extend(found)
        for p in found: pool_source_lines.append("iRule {0} -> {1}".format(irule, p))
    for raw, policy, exists_flag in policy_map:
        body_text = policy_defs.get(canonical_name(policy, policy_defs), "")
        found = extract_named_refs_fast(body_text, pool_alias_map)
        pools_from_policies.extend(found)
        for p in found: pool_source_lines.append("Policy {0} -> {1}".format(policy, p))
    all_pools = unique_list([top_pool] + pools_from_irules + pools_from_policies)

    pool_nodes = []; pool_monitors = []; pool_builtin_monitors = []
    for p in all_pools:
        if exists_in_registry(p, pools):
            pk = canonical_name(p, pools)
            pool_nodes.extend(pools[pk].get("nodes", []))
            pool_monitors.extend(pools[pk].get("monitors", []))
            pool_builtin_monitors.extend(pools[pk].get("builtin_monitors", []))
    pool_nodes = unique_list(pool_nodes); pool_monitors = unique_list(pool_monitors); pool_builtin_monitors = unique_list(pool_builtin_monitors)

    data_groups_from_irules = []; data_groups_from_policies = []; dg_source_lines = []
    for raw, irule, exists_flag in irule_map:
        dgs = extract_named_refs_fast(rule_defs.get(canonical_name(irule, rule_defs), ""), data_group_alias_map)
        data_groups_from_irules.extend(dgs)
        for dg in dgs: dg_source_lines.append("iRule {0} -> {1}".format(irule, dg))
    for raw, policy, exists_flag in policy_map:
        dgs = extract_named_refs_fast(policy_defs.get(canonical_name(policy, policy_defs), ""), data_group_alias_map)
        data_groups_from_policies.extend(dgs)
        for dg in dgs: dg_source_lines.append("Policy {0} -> {1}".format(policy, dg))
    all_data_groups = unique_list(data_groups_from_irules + data_groups_from_policies)

    client_cert_keys = []
    for prof in client_ssl_profiles:
        d = client_profiles.get(canonical_name(prof, client_profiles), {})
        client_cert_keys.append((prof, d.get("cert", "-"), d.get("key", "-")))
    server_cert_keys = []
    for prof in server_ssl_profiles:
        d = server_profiles.get(canonical_name(prof, server_profiles), {})
        server_cert_keys.append((prof, d.get("cert", "-"), d.get("key", "-")))

    item = {"virtual": vs_name, "top_pool": top_pool, "pools": all_pools, "pools_from_irules": unique_list(pools_from_irules), "pools_from_policies": unique_list(pools_from_policies), "pool_source_lines": unique_list(pool_source_lines), "raw_pool": raw_pool, "nodes": pool_nodes, "pool_monitors": pool_monitors, "pool_builtin_monitors": pool_builtin_monitors, "snat": snat, "policies": policies, "policy_map": policy_map, "irules": irules, "irule_map": irule_map, "data_groups": all_data_groups, "data_groups_from_irules": unique_list(data_groups_from_irules), "data_groups_from_policies": unique_list(data_groups_from_policies), "data_group_source_lines": unique_list(dg_source_lines), "persistence_profiles": persistence, "builtin_persistence": builtin_persistence, "one_connect_profiles": one_connect_profiles_list, "tcp_profiles": tcp_profile_list, "builtin_profiles": builtin_profiles, "unknown_profiles": unknown_profiles, "client_ssl_profiles": client_ssl_profiles, "client_cert_keys": client_cert_keys, "server_ssl_profiles": server_ssl_profiles, "server_cert_keys": server_cert_keys, "destination_raw": destination_raw, "destination_ip": destination_ip, "dns_fqdn": vs_to_fqdn(vs_name)}
    all_virtual_inventory[vs_name] = item

    add_ref(object_refs, "snat pool", snat, vs_name)
    for typ, values in [("pool", all_pools), ("one-connect profile", one_connect_profiles_list), ("tcp profile", tcp_profile_list), ("client ssl profile", client_ssl_profiles), ("server ssl profile", server_ssl_profiles), ("node", pool_nodes), ("pool monitor", pool_monitors), ("persistence profile", persistence), ("policy", policies), ("irule", irules), ("data-group", all_data_groups)]:
        for value in values: add_ref(object_refs, typ, value, vs_name)
    for prof, cert, key in client_cert_keys:
        add_ref(object_refs, "client ssl key", key, vs_name); add_ref(object_refs, "client ssl cert", cert, vs_name)
    for prof, cert, key in server_cert_keys:
        add_ref(object_refs, "server ssl key", key, vs_name); add_ref(object_refs, "server ssl cert", cert, vs_name)
    for mon in pool_monitors:
        add_ref(object_refs, "pool monitor cert", get_monitor_cert(mon), vs_name); add_ref(object_refs, "pool monitor key", get_monitor_key(mon), vs_name)

# Selected scope and headers considered internal to requested deletion
found = []; not_found = []; processed_objects = []
selected_scope = set(); selected_objects = defaultdict(set); selected_headers = set()
for requested_vs in requested_list:
    item = all_virtual_inventory.get(requested_vs)
    if item is None:
        not_found.append(requested_vs); continue
    found.append(requested_vs); processed_objects.append(item)
    selected_scope.add(objkey("virtual server", requested_vs)); selected_objects["virtual server"].add(requested_vs); selected_headers.add("ltm virtual {0}".format(requested_vs))
    for policy in item["policies"]: selected_headers.add("ltm policy {0}".format(policy))
    for irule in item["irules"]: selected_headers.add("ltm rule {0}".format(irule))
    for typ, values in [("pool", item["pools"]), ("snat pool", [item["snat"]]), ("node", item["nodes"]), ("pool monitor", item["pool_monitors"]), ("persistence profile", item["persistence_profiles"]), ("one-connect profile", item["one_connect_profiles"]), ("tcp profile", item["tcp_profiles"]), ("client ssl profile", item["client_ssl_profiles"]), ("server ssl profile", item["server_ssl_profiles"]), ("policy", item["policies"]), ("irule", item["irules"]), ("data-group", item["data_groups"] )]:
        for v in values:
            if v and v != "-": selected_objects[typ].add(v); selected_scope.add(objkey(typ, v))
    for mon in item["pool_monitors"]:
        cert = get_monitor_cert(mon); key = get_monitor_key(mon)
        if cert != "-": selected_objects["pool monitor cert"].add(cert); selected_scope.add(objkey("pool monitor cert", cert))
        if key != "-": selected_objects["pool monitor key"].add(key); selected_scope.add(objkey("pool monitor key", key))
    for prof, cert, key in item["client_cert_keys"]:
        if key != "-": selected_objects["client ssl key"].add(key); selected_scope.add(objkey("client ssl key", key))
        if cert != "-": selected_objects["client ssl cert"].add(cert); selected_scope.add(objkey("client ssl cert", cert))
    for prof, cert, key in item["server_cert_keys"]:
        if key != "-": selected_objects["server ssl key"].add(key); selected_scope.add(objkey("server ssl key", key))
        if cert != "-": selected_objects["server ssl cert"].add(cert); selected_scope.add(objkey("server ssl cert", cert))

# Expand through defaults-from parents
expanded_defaults = defaultdict(dict)
queue = deque(list(selected_scope))
while queue:
    key = queue.popleft(); typ, name = split_objkey(key)
    if typ in GRAPH_PROFILE_TYPES and name in defaults_parent.get(typ, {}):
        parent = defaults_parent[typ][name]; pkey = objkey(typ, parent)
        expanded_defaults[typ][parent] = name
        if pkey not in selected_scope:
            selected_scope.add(pkey); selected_objects[typ].add(parent); queue.append(pkey)

# Orphaned pool detection after ltm/apm/afm scan
orphaned_pools = []
for p in sorted(pools.keys()):
    if not pool_module_refs.get(p): orphaned_pools.append(p)
orphaned_pool_set = set(orphaned_pools)
node_to_pools = defaultdict(set); monitor_to_pools = defaultdict(set)
for p, pdata in pools.items():
    for n in pdata.get("nodes", []): node_to_pools[n].add(p)
    for m in pdata.get("monitors", []): monitor_to_pools[m].add(p)

# Safety helpers
def registry_for_type(typ):
    if typ == "virtual server": return virtuals
    if typ == "policy": return policy_defs
    if typ == "pool": return pools
    if typ == "pool monitor": return monitors
    if typ == "node": return node_defs
    if typ == "snat pool": return snatpool_defs
    if typ == "persistence profile": return persistence_profiles
    if typ == "one-connect profile": return oneconnect_profiles
    if typ == "tcp profile": return tcp_profiles
    if typ == "client ssl profile": return client_profiles
    if typ == "server ssl profile": return server_profiles
    if typ == "irule": return rule_defs
    if typ == "data-group": return data_groups
    return None


def is_builtin_object(typ, name):
    if typ == "pool monitor": return is_builtin(name, BUILT_IN_MONITORS)
    if typ == "persistence profile": return is_builtin(name, BUILT_IN_PERSISTENCE)
    if typ == "one-connect profile": return is_builtin(name, BUILT_IN_ONECONNECT_PROFILES)
    if typ == "tcp profile": return is_builtin(name, BUILT_IN_TCP_PROFILES)
    if typ == "client ssl profile": return is_builtin(name, BUILT_IN_CLIENT_SSL_PROFILES)
    if typ == "server ssl profile": return is_builtin(name, BUILT_IN_SERVER_SSL_PROFILES)
    return False


def object_exists(typ, name):
    if typ in ("client ssl key", "client ssl cert", "server ssl key", "server ssl cert", "pool monitor key", "pool monitor cert"): return name != "-"
    reg = registry_for_type(typ)
    if reg is None: return True
    return exists_in_registry(name, reg)


def defaults_outside_children(typ, name):
    outside = []
    for child in sorted(defaults_children.get(typ, {}).get(name, set())):
        if objkey(typ, child) not in selected_scope: outside.append(child)
    return outside


def external_pool_module_refs(pool_name):
    refs = []
    for h in pool_module_refs.get(pool_name, []):
        if h not in selected_headers: refs.append(h)
    return unique_list(refs)


def list_command(typ, name):
    if typ == "virtual server": return "tmsh list ltm virtual {0} one-line".format(name)
    if typ == "policy": return "tmsh list ltm policy {0} one-line".format(name)
    if typ == "pool": return "tmsh list ltm pool {0} one-line".format(name)
    if typ == "pool monitor": return "tmsh list ltm monitor {0} {1} one-line".format(get_monitor_type(name), name)
    if typ == "pool monitor cert": return "tmsh list sys crypto cert {0} one-line".format(name)
    if typ == "pool monitor key": return "tmsh list sys crypto key {0} one-line".format(name)
    if typ == "node": return "tmsh list ltm node {0} one-line".format(name)
    if typ == "snat pool": return "tmsh list ltm snatpool {0} one-line".format(name)
    if typ == "persistence profile": return "tmsh list ltm persistence {0} {1} one-line".format(get_persistence_type(name), name)
    if typ == "one-connect profile": return "tmsh list ltm profile one-connect {0} one-line".format(name)
    if typ == "tcp profile": return "tmsh list ltm profile tcp {0} one-line".format(name)
    if typ == "client ssl profile": return "tmsh list ltm profile client-ssl {0} one-line".format(name)
    if typ == "client ssl key": return "tmsh list sys crypto key {0} one-line".format(name)
    if typ == "client ssl cert": return "tmsh list sys crypto cert {0} one-line".format(name)
    if typ == "server ssl profile": return "tmsh list ltm profile server-ssl {0} one-line".format(name)
    if typ == "server ssl key": return "tmsh list sys crypto key {0} one-line".format(name)
    if typ == "server ssl cert": return "tmsh list sys crypto cert {0} one-line".format(name)
    if typ == "irule": return "tmsh list ltm rule {0} one-line".format(name)
    if typ == "data-group": return "tmsh list ltm data-group {0} {1} one-line".format(get_data_group_type(name), name)
    return "# unsupported list command for {0} {1}".format(typ, name)


def delete_command(typ, name):
    if typ == "virtual server": return "tmsh delete ltm virtual {0}".format(name)
    if typ == "policy": return "tmsh delete ltm policy {0}".format(name)
    if typ == "pool": return "tmsh delete ltm pool {0}".format(name)
    if typ == "pool monitor": return "tmsh delete ltm monitor {0} {1}".format(get_monitor_type(name), name)
    if typ == "pool monitor cert": return "tmsh delete sys crypto cert {0}".format(name)
    if typ == "pool monitor key": return "tmsh delete sys crypto key {0}".format(name)
    if typ == "node": return "tmsh delete ltm node {0}".format(name)
    if typ == "snat pool": return "tmsh delete ltm snatpool {0}".format(name)
    if typ == "persistence profile": return "tmsh delete ltm persistence {0} {1}".format(get_persistence_type(name), name)
    if typ == "one-connect profile": return "tmsh delete ltm profile one-connect {0}".format(name)
    if typ == "tcp profile": return "tmsh delete ltm profile tcp {0}".format(name)
    if typ == "client ssl profile": return "tmsh delete ltm profile client-ssl {0}".format(name)
    if typ == "client ssl key": return "tmsh delete sys crypto key {0}".format(name)
    if typ == "client ssl cert": return "tmsh delete sys crypto cert {0}".format(name)
    if typ == "server ssl profile": return "tmsh delete ltm profile server-ssl {0}".format(name)
    if typ == "server ssl key": return "tmsh delete sys crypto key {0}".format(name)
    if typ == "server ssl cert": return "tmsh delete sys crypto cert {0}".format(name)
    if typ == "irule": return "tmsh delete ltm rule {0}".format(name)
    if typ == "data-group": return "tmsh delete ltm data-group {0} {1}".format(get_data_group_type(name), name)
    return "# unsupported delete command for {0} {1}".format(typ, name)

ordered_groups = ["virtual server", "policy", "pool", "pool monitor", "pool monitor cert", "pool monitor key", "node", "snat pool", "persistence profile", "one-connect profile", "tcp profile", "client ssl profile", "client ssl cert", "client ssl key", "server ssl profile", "server ssl cert", "server ssl key", "irule", "data-group"]
list_groups = defaultdict(dict); delete_groups = defaultdict(dict); skipped_groups = defaultdict(dict); invalid_groups = defaultdict(dict); builtin_groups = defaultdict(dict); defaults_scope_groups = defaultdict(dict); defaults_external_groups = defaultdict(dict); pool_external_groups = defaultdict(dict)

for typ in ordered_groups:
    for name in sorted(selected_objects.get(typ, set())):
        if not name or name == "-": continue
        if is_builtin_object(typ, name): builtin_groups[typ][name] = "built-in F5 object; not eligible for delete"; continue
        if not object_exists(typ, name): invalid_groups[typ][name] = "referenced object was not found in expected config definitions"; continue
        outside_children = defaults_outside_children(typ, name)
        if outside_children: defaults_external_groups[typ][name] = outside_children; continue
        if typ == "pool":
            ext = external_pool_module_refs(name)
            if ext:
                pool_external_groups[typ][name] = ext
                continue
        if not is_safe_vs_scope(typ, name): skipped_groups[typ][name] = get_external_vip_refs(typ, name); continue
        if typ in GRAPH_PROFILE_TYPES and name in expanded_defaults.get(typ, {}): defaults_scope_groups[typ][name] = expanded_defaults[typ][name]
        add_command(list_groups, typ, name, list_command(typ, name)); add_command(delete_groups, typ, name, delete_command(typ, name))

# Orphaned pool commands, protected by external ltm/apm/afm scan by definition
orphan_pool_list_commands = []; orphan_pool_delete_commands = []; orphan_monitor_list_commands = []; orphan_monitor_delete_commands = []; orphan_node_list_commands = []; orphan_node_delete_commands = []
orphan_skipped_nodes = defaultdict(list); orphan_skipped_monitors = defaultdict(list); orphan_skipped_default_monitors = defaultdict(list)
for p in orphaned_pools:
    orphan_pool_list_commands.append("tmsh list ltm pool {0} one-line".format(p)); orphan_pool_delete_commands.append("tmsh delete ltm pool {0}".format(p))
    for mon in pools[p].get("monitors", []):
        outside = sorted([x for x in monitor_to_pools[mon] if x not in orphaned_pool_set])
        if outside: orphan_skipped_monitors[mon] = outside; continue
        child_outside = []
        for child in sorted(defaults_children.get("pool monitor", {}).get(mon, set())):
            child_pools = monitor_to_pools.get(child, set())
            if [x for x in child_pools if x not in orphaned_pool_set]: child_outside.append(child)
        if child_outside: orphan_skipped_default_monitors[mon] = child_outside; continue
        if not is_builtin(mon, BUILT_IN_MONITORS) and exists_in_registry(mon, monitors):
            orphan_monitor_list_commands.append("tmsh list ltm monitor {0} {1} one-line".format(get_monitor_type(mon), mon))
            orphan_monitor_delete_commands.append("tmsh delete ltm monitor {0} {1}".format(get_monitor_type(mon), mon))
    for node in pools[p].get("nodes", []):
        outside = sorted([x for x in node_to_pools[node] if x not in orphaned_pool_set])
        if outside: orphan_skipped_nodes[node] = outside
        elif exists_in_registry(node, node_defs):
            orphan_node_list_commands.append("tmsh list ltm node {0} one-line".format(node)); orphan_node_delete_commands.append("tmsh delete ltm node {0}".format(node))
orphan_pool_list_commands = unique_list(orphan_pool_list_commands); orphan_pool_delete_commands = unique_list(orphan_pool_delete_commands); orphan_monitor_list_commands = unique_list(orphan_monitor_list_commands); orphan_monitor_delete_commands = unique_list(orphan_monitor_delete_commands); orphan_node_list_commands = unique_list(orphan_node_list_commands); orphan_node_delete_commands = unique_list(orphan_node_delete_commands)

# Output
for item in processed_objects:
    print("=" * 80)
    print("Virtual Server : {0}".format(item["virtual"]))
    print("Destination    : {0}".format(item["destination_raw"]))
    print("Destination IP : {0}".format(item["destination_ip"]))
    print("DNS FQDN       : {0}".format(item["dns_fqdn"]))
    print("Top Pool       : {0}".format(item["top_pool"]))
    print("All Pool(s)    : {0}".format(", ".join(item["pools"]) if item["pools"] else "-"))
    if item["pools_from_irules"]: print("    From iRules  : {0}".format(", ".join(item["pools_from_irules"])))
    if item["pools_from_policies"]: print("    From Policies: {0}".format(", ".join(item["pools_from_policies"])))
    if item["pool_source_lines"]:
        print("Pool Diagnostics:")
        for line in item["pool_source_lines"]: print("    {0}".format(line))
    print("Nodes          : {0}".format(", ".join(item["nodes"]) if item["nodes"] else "-"))
    if item["pool_monitors"] or item["pool_builtin_monitors"]:
        print("Pool Monitor(s):")
        for mon in item["pool_monitors"]:
            print("    {0}".format(mon)); print("        Type : {0}".format(get_monitor_type(mon))); print("        Cert : {0}".format(get_monitor_cert(mon))); print("        Key  : {0}".format(get_monitor_key(mon)))
        for mon in item["pool_builtin_monitors"]: print("    {0}  [built-in, ignored for delete]".format(mon))
    else: print("Pool Monitor(s): -")
    print("SNAT Pool      : {0}".format(item["snat"]))
    print("Persistence    : {0}".format(", ".join(item["persistence_profiles"]) if item["persistence_profiles"] else "-"))
    if item["builtin_persistence"]: print("Built-in Persistence ignored for delete: {0}".format(", ".join(item["builtin_persistence"])))
    print("OneConnect     : {0}".format(", ".join(item["one_connect_profiles"]) if item["one_connect_profiles"] else "-"))
    print("TCP Profile(s) : {0}".format(", ".join(item["tcp_profiles"]) if item["tcp_profiles"] else "-"))
    print("Policy         : {0}".format(", ".join(item["policies"]) if item["policies"] else "-"))
    print("iRules         : {0}".format(", ".join(item["irules"]) if item["irules"] else "-"))
    print("Data Group(s)  : {0}".format(", ".join(item["data_groups"]) if item["data_groups"] else "-"))
    if item["policy_map"]:
        print("Policy Diagnostics:")
        for raw, canonical, exists_flag in item["policy_map"]: print("    raw={0} canonical={1} found={2}".format(raw, canonical, exists_flag))
    if item["irule_map"]:
        print("iRule Diagnostics:")
        for raw, canonical, exists_flag in item["irule_map"]: print("    raw={0} canonical={1} found={2}".format(raw, canonical, exists_flag))
    print()

print("=" * 80)
print("SUMMARY")
print("Requested virtual servers : {0}".format(len(requested_list)))
print("Found                     : {0}".format(len(found)))
print("Not found                 : {0}".format(len(not_found)))
if not_found:
    print("\nNot found virtual servers:")
    for vs in not_found: print("  {0}".format(vs))

print("\n" + "=" * 80)
print("POOL DEPENDENCY SCAN - LTM/APM/AFM")
print("Pools listed here are referenced by objects outside the selected VS/policy/iRule deletion scope.")
print("Delete commands are not generated for these pools. This protects APM/AAA/AFM dependencies such as AAA LDAP pools.\n")
if pool_external_groups:
    for group in sorted(pool_external_groups.keys()):
        print("# {0}".format(group.upper()))
        for pool_name in sorted(pool_external_groups[group].keys()):
            print("Pool: {0}".format(pool_name))
            print("Referenced by ltm/apm/afm objects outside selected scope:")
            for ref in pool_external_groups[group][pool_name]: print("  {0}".format(ref))
            print()
else:
    print("No selected pools were blocked by external ltm/apm/afm module references.")

print("\n" + "=" * 80)
print("DEFAULTS-FROM FULL DEPENDENCY ANALYSIS")
print("Parent profiles discovered through selected child objects are added to deletion scope.")
print("They are deleted only when all defaults-from child references are also inside deletion scope and there are no external VS references.\n")
if defaults_scope_groups:
    print("# DEFAULTS-FROM PARENTS INCLUDED IN DELETE SCOPE")
    for typ in sorted(defaults_scope_groups.keys()):
        for parent in sorted(defaults_scope_groups[typ].keys()):
            print("Object: {0}".format(parent)); print("Type  : {0}".format(typ)); print("Reason: required as defaults-from parent by selected child {0}".format(defaults_scope_groups[typ][parent])); print()
else: print("No defaults-from parent objects were added to the deletion scope.")
if defaults_external_groups:
    print("# DEFAULTS-FROM PARENTS PROTECTED BY CHILDREN OUTSIDE DELETE SCOPE")
    for typ in sorted(defaults_external_groups.keys()):
        for parent in sorted(defaults_external_groups[typ].keys()):
            print("Object: {0}".format(parent)); print("Type  : {0}".format(typ)); print("Used as defaults-from by child objects outside deletion scope:")
            for child in defaults_external_groups[typ][parent]: print("  {0}".format(child))
            print()
else: print("No selected defaults-from parents were blocked by children outside deletion scope.")

print("\n" + "=" * 80)
print("GLOBAL ORPHANED POOLS")
print("Pools listed here are defined in ltm pool and have no references in scanned ltm/apm/afm blocks, excluding the pool definition itself.")
print("Orphaned data-groups are intentionally not reported or deleted in this version.\n")
if orphaned_pools:
    for p in orphaned_pools:
        print("Object: {0}".format(p)); print("Reason: no references found in ltm/apm/afm module blocks")
        print("Nodes : {0}".format(", ".join(pools[p].get("nodes", [])) if pools[p].get("nodes", []) else "-"))
        mons = pools[p].get("monitors", []) + pools[p].get("builtin_monitors", [])
        print("Monitors: {0}".format(", ".join(mons) if mons else "-")); print()
else: print("No orphaned pools detected.")

print("\n" + "=" * 80)
print("ORPHANED POOL SHARED NODE/MONITOR SAFETY CHECK")
print("Nodes or monitors listed here belong to orphaned pools but are also used by non-orphaned pools, or monitor defaults-from children outside orphaned scope.\n")
if orphan_skipped_nodes or orphan_skipped_monitors or orphan_skipped_default_monitors:
    if orphan_skipped_nodes:
        print("# NODES USED BY NON-ORPHANED POOLS")
        for node in sorted(orphan_skipped_nodes.keys()):
            print("Object: {0}".format(node)); print("Used by non-orphaned pools:")
            for p in orphan_skipped_nodes[node]: print("  {0}".format(p))
            print()
    if orphan_skipped_monitors:
        print("# MONITORS USED BY NON-ORPHANED POOLS")
        for mon in sorted(orphan_skipped_monitors.keys()):
            print("Object: {0}".format(mon)); print("Used by non-orphaned pools:")
            for p in orphan_skipped_monitors[mon]: print("  {0}".format(p))
            print()
    if orphan_skipped_default_monitors:
        print("# MONITORS PROTECTED BY DEFAULTS-FROM CHILDREN OUTSIDE ORPHANED SCOPE")
        for mon in sorted(orphan_skipped_default_monitors.keys()):
            print("Object: {0}".format(mon)); print("Used as defaults-from by child monitors outside orphaned pool scope:")
            for child in orphan_skipped_default_monitors[mon]: print("  {0}".format(child))
            print()
else: print("No shared orphan-pool nodes or monitors detected.")

print("\n" + "=" * 80)
print("DIG +SHORT LOOKUP FOR DESTINATION IP")
print("Command template: {0} {1} <destination_ip>".format(DIG_COMMAND, DIG_OPTIONS))
print("Format: Virtual Server | Destination IP | DIG result")
print("Note: this uses reverse DNS/PTR lookup: dig +short -x <IP>.\n")
for item in processed_objects:
    ip = item["destination_ip"]
    if ip == "-": print("{0} | {1} | -".format(item["virtual"], ip))
    else:
        res = dig_short_lookup(ip)
        if res:
            for record in res: print("{0} | {1} | {2}".format(item["virtual"], ip, record))
        else: print("{0} | {1} | -".format(item["virtual"], ip))

print("\n" + "=" * 80)
print("DNS DELETION REQUESTS")
print("Format: Action: Delete  Record Type: A  FQDN: <VIP>  IP Address: <destination IP>  View: Internal")
print("Duplicate DNS deletion requests are suppressed based on unique FQDN/IP pairs.\n")
seen_dns = set()
for item in processed_objects:
    key = (item["dns_fqdn"], item["destination_ip"])
    if key in seen_dns: continue
    seen_dns.add(key)
    print("Action: Delete  Record Type: A  FQDN: {0}  IP Address: {1}  View: Internal".format(item["dns_fqdn"], item["destination_ip"]))

print("\n" + "=" * 80)
print("BUILT-IN OBJECTS - NOT ELIGIBLE FOR DELETE")
any_builtin = False
for group in sorted(builtin_groups.keys()):
    if not builtin_groups[group]: continue
    any_builtin = True; print("# {0}".format(group.upper()))
    for obj in sorted(builtin_groups[group].keys()): print("Object: {0}".format(obj)); print("Reason: {0}".format(builtin_groups[group][obj])); print()
if not any_builtin: print("No built-in objects detected for selected virtual servers.")

print("\n" + "=" * 80)
print("INVALID OBJECT REFERENCES")
any_invalid = False
for group in ordered_groups:
    if not invalid_groups.get(group, {}): continue
    any_invalid = True; print("# {0}".format(group.upper()))
    for obj in sorted(invalid_groups[group].keys()): print("Object: {0}".format(obj)); print("Reason: {0}".format(invalid_groups[group][obj])); print()
if not any_invalid: print("No invalid object references detected for selected virtual servers.")

print("\n" + "=" * 80)
print("SHARED OBJECT SAFETY CHECK")
print("Objects listed here are used by virtual servers outside your pasted deletion list.")
print("These objects are protected and list/delete commands are not generated for them.\n")
any_shared = False
for group in ordered_groups:
    if not skipped_groups.get(group, {}): continue
    any_shared = True; print("# {0}".format(group.upper()))
    for obj in sorted(skipped_groups[group].keys()):
        print("Object: {0}".format(obj)); print("Used by virtual servers not selected for deletion:")
        for vip in skipped_groups[group][obj]: print("  {0}".format(vip))
        print()
if not any_shared: print("No shared object references found against virtual servers outside your pasted list.")

print("\n" + "=" * 80)
print("LIST COMMANDS - ONE-LINE")
print("Only existing and safe-to-delete objects in the computed dependency graph are listed below.")
print("Objects with external ltm/apm/afm pool refs, external VS refs, defaults-from child refs outside scope, invalid refs, or built-in status are excluded.")
print("A shell delay is printed after each command to avoid lost output on busy systems.\n")
for group in ordered_groups:
    print("# {0}".format(group.upper()))
    commands = list_groups.get(group, {})
    if not commands: print("# none")
    else:
        for _, cmd in sorted(commands.items()): print(cmd); print(COMMAND_DELAY)
    print()

print("\n" + "=" * 80)
print("DELETE COMMANDS - REVIEW CAREFULLY BEFORE RUNNING")
print("Only existing and safe-to-delete objects in the computed dependency graph are listed below.")
print("Objects with external ltm/apm/afm pool refs, external VS refs, defaults-from child refs outside scope, invalid refs, or built-in status are excluded.")
print("The script does NOT execute delete commands.")
print("A shell delay is printed after each command to avoid lost output on busy systems.\n")
for group in ordered_groups:
    print("# {0}".format(group.upper()))
    commands = delete_groups.get(group, {})
    if not commands: print("# none")
    else:
        for _, cmd in sorted(commands.items()): print(cmd); print(COMMAND_DELAY)
    print()

print("\n" + "=" * 80)
print("ORPHANED POOL LIST COMMANDS - GLOBAL")
print("These commands are generated for pools with no references in scanned ltm/apm/afm module blocks.")
print("They are independent of the pasted VS list. Review carefully before running.\n")
for title, commands in [("# POOLS", orphan_pool_list_commands), ("# MONITORS", orphan_monitor_list_commands), ("# NODES", orphan_node_list_commands)]:
    print(title)
    if commands:
        for cmd in commands: print(cmd); print(COMMAND_DELAY)
    else: print("# none")
    print()

print("\n" + "=" * 80)
print("ORPHANED POOL DELETE COMMANDS - GLOBAL REVIEW CAREFULLY")
print("These commands are generated for orphaned pools and their safe-to-delete monitors/nodes.")
print("They are independent of the pasted VS list and the script does NOT execute them.\n")
for title, commands in [("# POOLS", orphan_pool_delete_commands), ("# MONITORS", orphan_monitor_delete_commands), ("# NODES", orphan_node_delete_commands)]:
    print(title)
    if commands:
        for cmd in commands: print(cmd); print(COMMAND_DELAY)
    else: print("# none")
    print()

