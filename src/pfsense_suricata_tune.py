"""Surgical XML patches for Suricata package settings on pfSense.

Phase 7b.2 ships a single Apply handler: flip the per-instance
``<runmode>`` key from ``autofp`` to ``workers`` so Suricata uses
one inspection thread per CPU core on the Netgate 4200's 4-core ARM.

Why XML surgery, not YAML editing
---------------------------------
``/usr/local/etc/suricata/suricata_<uuid>_<iface>/suricata.yaml`` is
regenerated from ``/cf/conf/config.xml`` every time the operator
saves anything in the pfSense Suricata GUI. Patching the YAML
directly would survive until the very next GUI interaction; patching
the XML makes the change stick through every reload scenario. Same
"no tech debt" doctrine as Phase 7h.

YAML regeneration
-----------------
After the XML change we have to tell pfSense to rebuild the YAML
from the new XML and restart Suricata. pfSense's Suricata package
ships a PHP helper suite that does exactly this; we invoke it via
``php -r`` so the rebuild logic stays in the package code rather
than being duplicated here. If the helper is unavailable (older
Suricata package) we fall back to a vanilla service restart — which
is less guaranteed but still generally works since pfSense rebuilds
the YAML lazily on restart.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.pfsense_ssh import PfSenseSSH

logger = logging.getLogger("ward_soar.pfsense_suricata_tune")


#: Remote path of the live config.
REMOTE_CONFIG_XML_PATH = "/cf/conf/config.xml"


@dataclass(frozen=True)
class SuricataTuneResult:
    """Outcome of a single Suricata-tune operation."""

    success: bool
    instances_changed: int
    message: str


# ---------------------------------------------------------------------------
# Pure transform — unit-tested in isolation.
# ---------------------------------------------------------------------------

#: Regex locating one Suricata instance record (one ``<rule>`` element
#: under ``<installedpackages><suricata>``). We anchor on ``<uuid>``
#: because the Suricata package guarantees each instance has one and
#: the top-level ``<rule>`` element name collides with pf rule records
#: elsewhere in config.xml.
_SURICATA_INSTANCE_RE = re.compile(
    r"(?P<open>[ \t]*<rule>\s*\n)"
    r"(?P<body>(?:(?!<rule>).)*?<uuid>[0-9a-fA-F]+</uuid>.*?)"
    r"(?P<close>[ \t]*</rule>\s*\n)",
    re.DOTALL,
)


def patch_runmode(xml_text: str, *, target: str = "workers") -> tuple[str, int]:
    """Set ``<runmode>`` to ``target`` on every Suricata instance.

    The transform is idempotent: instances whose ``<runmode>`` already
    equals ``target`` are emitted byte-identical. Instances without a
    ``<runmode>`` tag at all get one inserted immediately after the
    ``<uuid>`` line so the GUI's later regeneration sees a canonical
    shape.

    Args:
        xml_text: Full ``config.xml`` contents.
        target: Desired runmode value. Only ``workers``, ``autofp``,
            or ``single`` are valid Suricata runmodes; the caller is
            responsible for passing a sensible value.

    Returns:
        ``(new_xml, instances_changed)`` — ``instances_changed`` is
        the number of ``<rule>`` elements whose body differs from the
        input. Zero means fully idempotent no-op.
    """
    if target not in {"workers", "autofp", "single"}:
        raise ValueError(f"invalid Suricata runmode: {target!r}")

    changed_count = 0
    runmode_re = re.compile(r"<runmode>[^<]*</runmode>")
    uuid_re = re.compile(r"(<uuid>[0-9a-fA-F]+</uuid>\s*\n)")

    def _patch_instance(match: "re.Match[str]") -> str:
        nonlocal changed_count
        body = match.group("body")

        # If the instance already has <runmode>target</runmode>,
        # emit it byte-identical so a re-Apply is a true no-op.
        existing = runmode_re.search(body)
        if existing and existing.group(0) == f"<runmode>{target}</runmode>":
            return match.group(0)

        if existing:
            new_body = runmode_re.sub(f"<runmode>{target}</runmode>", body, count=1)
        else:
            # No runmode tag yet — insert one right after <uuid>. The
            # pfSense package tolerates missing optional keys but the
            # regen template prefers them explicit, and keeping the
            # insertion anchored to <uuid> makes the diff minimal.
            uuid_match = uuid_re.search(body)
            if uuid_match is None:
                return match.group(0)  # not a real Suricata rule — skip
            indent_match = re.match(r"([ \t]*)<uuid>", uuid_match.group(0))
            indent = indent_match.group(1) if indent_match else "\t\t\t\t"
            insertion = f"{indent}<runmode>{target}</runmode>\n"
            new_body = body.replace(
                uuid_match.group(0),
                uuid_match.group(0) + insertion,
                1,
            )

        changed_count += 1
        return match.group("open") + new_body + match.group("close")

    new_xml = _SURICATA_INSTANCE_RE.sub(_patch_instance, xml_text)
    return new_xml, changed_count


# ---------------------------------------------------------------------------
# SSH-driven orchestrator
# ---------------------------------------------------------------------------

#: Heredoc sentinel for pushing the updated config.xml.
_XML_SENTINEL = "__WARDSOAR_SURI_XML_EOF__"

#: Heredoc sentinel for the PHP regeneration script.
_PHP_SENTINEL = "__WARDSOAR_SURI_PHP_EOF__"

#: PHP script that rebuilds every instance's suricata.yaml from the
#: XML we just pushed and restarts the Suricata daemon.
#:
#: Design notes learnt from v0.8.1:
#:
#: * ``php -r`` with complex single-quoted code proved fragile — the
#:   SSH layer adds another quoting layer that mangled our braces.
#:   A heredoc-fed PHP script is transmitted verbatim and therefore
#:   reliable. We wrap the WHOLE thing in ``php -d display_errors=1``
#:   so any fatal error surfaces in stdout rather than silently
#:   leaving PHP's exit code at 0.
#:
#: * ``config_get_path`` is the modern accessor but older Suricata
#:   packages use ``$config`` directly. We read via the global so
#:   the code works on every supported pfSense version.
#:
#: * ``suricata_sync_on_changes`` is the canonical entry point
#:   pfSense calls after a GUI save — the XML description registers
#:   it as ``<custom_php_resync_config_command>``. It internally
#:   regenerates every instance's YAML AND restarts the daemon. If
#:   it's unavailable (very old package), we fall back to calling
#:   ``suricata_create_yaml`` on each rule ourselves, then explicit
#:   ``rc.d restart``.
#:
#: * Every branch emits a tag line (``ACTION: ...``) that the caller
#:   can grep to diagnose in-transit issues without having to SSH
#:   manually.
#: Canonical pfSense regen via ``write_config()`` — the SAME entry
#: point the webGUI save handler uses. Built with ``{target}`` as a
#: placeholder so the same template covers workers/autofp/single.
#:
#: Why this is the definitive approach (v0.8.4)
#: --------------------------------------------
#: Previous versions (0.8.1-0.8.3) tried to reproduce pfSense's save
#: flow step by step: chirurgical XML regex + guess a regen function
#: (``suricata_sync_on_changes`` was wrong — it's the HA hook, not
#: the YAML regen; ``suricata_create_yaml`` is right but requires
#: correct PHP context and hand-rolled per-rule iteration). Every
#: release we discovered another pfSense internal we had guessed
#: wrong.
#:
#: ``write_config()`` is pfSense's public, stable API for "commit a
#: config change". It:
#:   1. Writes ``$config`` atomically to ``/cf/conf/config.xml``.
#:   2. Bumps the config revision number.
#:   3. Fires every installed package's ``<custom_php_resync_config_command>``.
#:      For Suricata this regenerates every instance's YAML.
#:
#: We mutate the in-memory ``$config``, call write_config, then as a
#: belt-and-braces safeguard also call ``suricata_create_yaml`` per
#: rule in case the package hook is a no-op on this version.
_PHP_WRITECONFIG_TEMPLATE = """<?php
error_reporting(E_ALL);
require_once("globals.inc");
require_once("config.inc");
require_once("functions.inc");
require_once("/usr/local/pkg/suricata/suricata.inc");

// Print the pfSense version so the operator's log makes it obvious
// which API family we're running on. Useful when diagnosing across
// pfSense 24.x / 25.x / future 26.x upgrades.
echo "PFSENSE_VERSION=" . trim(@file_get_contents("/etc/version") ?: "?") . "\\n";

// ------------------------------------------------------------------
// Load Suricata rules — try the modern config API first (config_get_path,
// introduced in pfSense Plus 23.09 / CE 2.7 and likely mandatory in
// future major releases) and fall back to the legacy $config global.
// This gives us one script that works from pfSense 2.5 up to the
// yet-to-be-released 26.x without changes.
// ------------------------------------------------------------------
global $config;
if (function_exists("config_get_path")) {
    $rules = config_get_path("installedpackages/suricata/rule", []);
    echo "API: config_get_path\\n";
} else {
    $rules = $config["installedpackages"]["suricata"]["rule"] ?? [];
    echo "API: legacy_config_global\\n";
}
if (!is_array($rules)) { $rules = []; }

if (count($rules) === 0) {
    echo "ACTION: NO_RULES\\n";
    exit(2);
}
echo "RULES_COUNT=" . count($rules) . "\\n";

// ------------------------------------------------------------------
// Mutate in place. After this loop, the in-memory config reflects
// the desired state — exactly as if the GUI form handler had applied
// it. We prefer config_set_path (explicit API) over direct array
// mutation when the setter is available.
// ------------------------------------------------------------------
$changed = 0;
foreach ($rules as $i => $r) {
    $old = $r["runmode"] ?? "(missing)";
    echo "RULE uuid=" . ($r["uuid"] ?? "?") . " runmode_before=$old\\n";
    if ($old !== "__TARGET__") {
        if (function_exists("config_set_path")) {
            config_set_path("installedpackages/suricata/rule/$i/runmode", "__TARGET__");
        } else {
            $config["installedpackages"]["suricata"]["rule"][$i]["runmode"] = "__TARGET__";
        }
        $rules[$i]["runmode"] = "__TARGET__";  // keep local copy in sync for later loop
        $changed++;
    }
}
echo "CHANGED=$changed\\n";

if ($changed > 0) {
    // write_config is the canonical commit — unchanged API since
    // pfSense 2.0 (2011). Writes /cf/conf/config.xml atomically AND
    // fires every installed package's resync hook in one step.
    write_config("WardSOAR: set Suricata runmode=__TARGET__ via Apply");
    echo "ACTION: write_config\\n";
} else {
    echo "ACTION: no_change_needed\\n";
}

// ------------------------------------------------------------------
// Belt-and-braces: whether or not we called write_config, make sure
// every instance's YAML is in sync with the newly-committed config.
// This covers (a) the case where write_config's hook is a no-op on
// this package version and (b) a previous partial Apply that left
// XML and YAML out of sync.
// ------------------------------------------------------------------
if (function_exists("suricata_create_yaml")) {
    $n = 0;
    foreach ($rules as $r) {
        $uuid = $r["uuid"] ?? "?";
        $iface = $r["interface"] ?? "?";
        $if_real = function_exists("convert_friendly_interface_to_real_interface_name")
            ? convert_friendly_interface_to_real_interface_name($iface)
            : $iface;
        echo "REGEN_TARGET=/usr/local/etc/suricata/suricata_{$uuid}_{$if_real}/suricata.yaml\\n";
        suricata_create_yaml($r);
        $n++;
    }
    echo "ACTION: suricata_create_yaml x$n\\n";
} else {
    echo "WARN: suricata_create_yaml missing — relying on write_config hook\\n";
}
"""


def _build_php_script(target: str) -> str:
    """Substitute the target runmode into the PHP template.

    Using a simple replacement rather than f-strings so every
    character of the PHP is copied verbatim — important because the
    script contains ``$``, ``{``, braces, and quotes that Python
    would otherwise try to interpret.
    """
    return _PHP_WRITECONFIG_TEMPLATE.replace("__TARGET__", target)


def _build_commit_payload(target: str) -> str:
    """Build the full SSH payload: PHP script (via heredoc) + restart.

    The PHP script both mutates config.xml AND regenerates YAMLs via
    ``write_config`` + ``suricata_create_yaml``, so Python's only job
    is to invoke it and then kick the service. No XML surgery, no
    extra ``cat >`` heredocs, just one PHP payload.
    """
    php_body = _build_php_script(target)
    return (
        f"php <<'{_PHP_SENTINEL}' 2>&1\n"
        f"{php_body}"
        f"{_PHP_SENTINEL}\n"
        "echo ---\n"
        "/usr/local/etc/rc.d/suricata onestop >/dev/null 2>&1 || true\n"
        "sleep 1\n"
        "/usr/local/etc/rc.d/suricata onestart 2>&1 | tail -5 || true\n"
        "sleep 3\n"
        "echo ---\n"
        "pgrep -lf '^/usr/local/bin/suricata' 2>/dev/null | head -5 || true\n"
    )


async def apply_suricata_runmode(
    ssh: "PfSenseSSH",
    target: str = "workers",
) -> SuricataTuneResult:
    """Flip every Suricata instance's runmode via pfSense's canonical path.

    **v0.8.4 — definitive implementation.** Previous iterations did
    XML regex surgery + tried to invoke internal regeneration
    functions (``suricata_sync_on_changes`` — turned out to be the HA
    hook, not the YAML regen). Each release uncovered another
    internal we had guessed wrong. This version avoids the whole
    class of bug by delegating to pfSense's own commit mechanism.

    Execution sequence:

    1. **Probe current state** — grep the live YAML. If it already
       matches ``target`` on every instance, we're done (true no-op).
    2. **Delegate to pfSense via PHP**. The heredoc-fed PHP script:

       * Mutates ``$config['installedpackages']['suricata']['rule'][*]['runmode']``
         in memory.
       * Calls ``write_config()`` — pfSense's documented, stable API
         for committing config changes. This atomically writes
         ``/cf/conf/config.xml`` AND fires every package's
         ``<custom_php_resync_config_command>``.
       * As belt-and-braces, also calls ``suricata_create_yaml()``
         per rule so the YAML is guaranteed to be in sync with the
         committed config.
    3. **Restart Suricata** so the regenerated YAML is loaded.
    4. **Verify**: grep the live YAML for ``runmode: <target>`` —
       retry up to 4 times because rc.d restart can lag.

    NetgateApplier takes a full ``config.xml`` backup before calling
    us and will restore it if the external verify fails.
    """
    if target not in {"workers", "autofp", "single"}:
        return SuricataTuneResult(False, 0, f"invalid runmode target: {target!r}")

    # Step 1 — probe live YAML to short-circuit on an already-sync'd box.
    verify_cmd = (
        "grep -E '^runmode:' /usr/local/etc/suricata/suricata_*/suricata.yaml "
        "2>/dev/null | head -5 || true"
    )
    ok_probe, probe = await ssh.run_read_only(verify_cmd, timeout=10)
    if ok_probe and probe.strip():
        # Count how many YAMLs match vs total. If every runmode: line
        # is already the target, bail out success-no-op.
        lines = [ln for ln in probe.splitlines() if "runmode:" in ln]
        if lines and all(f"runmode: {target}" in ln for ln in lines):
            logger.info(
                "apply_suricata_runmode: live YAML already runmode=%s across %d "
                "instance(s) — no-op",
                target,
                len(lines),
            )
            return SuricataTuneResult(
                True,
                0,
                f"all Suricata instances already run with runmode={target}",
            )

    # Step 2 + 3 — delegate to the canonical PHP commit path, then
    # restart the daemon. The whole mutation (XML write + YAML regen)
    # happens atomically inside write_config, so there is no window
    # where XML and YAML can disagree.
    payload = _build_commit_payload(target)
    logger.info("apply_suricata_runmode: invoking canonical commit path (target=%s)", target)
    ok, commit_out = await ssh.run_read_only(payload, timeout=120)
    logger.info(
        "apply_suricata_runmode: commit output:\n%s",
        commit_out[:2000],
    )
    if not ok:
        return SuricataTuneResult(
            False,
            0,
            f"commit (write_config + restart) failed: {commit_out[:300]}",
        )

    # Diagnose fast-failing conditions before the verify retry.
    if "NO_RULES" in commit_out:
        return SuricataTuneResult(
            False,
            0,
            "commit script found no Suricata rules in $config — PHP "
            "context did not load config.xml. Output: " + commit_out[:200],
        )
    # Extract CHANGED=N so we can fill instances_changed precisely.
    changed = 0
    for line in commit_out.splitlines():
        if line.startswith("CHANGED="):
            try:
                changed = int(line.split("=", 1)[1])
            except ValueError:
                pass
            break

    # Step 4 — verify with retry. Even when the PHP path is clean,
    # the rc.d restart can return before the YAML hits disk on slower
    # boxes. Four seconds total is plenty on the Netgate 4200.
    final_verify = ""
    for attempt in range(4):
        if attempt > 0:
            await asyncio.sleep(1)
        ok, final_verify = await ssh.run_read_only(verify_cmd, timeout=10)
        if ok and final_verify.strip():
            lines = [ln for ln in final_verify.splitlines() if "runmode:" in ln]
            if lines and all(f"runmode: {target}" in ln for ln in lines):
                break
    else:
        return SuricataTuneResult(
            False,
            changed,
            "verify failed — regenerated YAML does not show runmode="
            f"{target} after 4 attempts. Last grep: "
            f"{final_verify[:200]}. Commit output tail: {commit_out[-400:]}",
        )

    logger.warning(
        "apply_suricata_runmode: succeeded — %d instance(s) now run with runmode=%s",
        changed,
        target,
    )
    return SuricataTuneResult(
        True,
        changed,
        f"set runmode={target} via write_config ({changed} instance(s) changed)",
    )


__all__ = [
    "REMOTE_CONFIG_XML_PATH",
    "SuricataTuneResult",
    "apply_suricata_runmode",
    "patch_runmode",
]
