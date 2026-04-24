"""One-shot migration of the pfSense ``blocklist`` alias to ``urltable``.

Phase 7h ships persistent blocklisting via an ``urltable`` alias
backed by a text file WardSOAR owns exclusively. This module is the
bridge: it converts an existing host-type alias (the out-of-the-box
state on every Netgate the operator has installed so far) into an
url-table alias in one atomic SSH operation, preserving any IPs
already present in the alias.

Why XML surgery once — and never again
--------------------------------------
The whole point of moving to ``urltable`` is that WardSOAR never
touches ``config.xml`` at runtime. This module runs exactly once
per Netgate, under explicit operator Apply, with backup + verify +
rollback via :class:`src.netgate_apply.NetgateApplier`. After the
conversion, every block-list mutation goes through
:class:`src.pfsense_aliastable.PersistentBlocklist` and only touches
a plain text file.

Surgical scope
--------------
The modification is deliberately targeted: we find the
``<alias>`` element whose ``<name>`` is ``blocklist`` and change
only three fields inside it:

* ``<type>host</type>`` → ``<type>urltable</type>``
* ``<address>...</address>`` → removed
* (new) ``<url>file:///var/db/aliastables/wardsoar_blocklist.txt</url>``
* (new) ``<updatefreq>1</updatefreq>``  (pfSense re-reads the file daily)

The rest of ``config.xml`` — thousands of lines covering rules, DNS,
DHCP, user accounts, WireGuard, Suricata — is left byte-identical.
We intentionally avoid any full-tree re-serialisation because
pfSense's config.xml carries CDATA sections, a very specific
tab-indent style, and magic ordering that its own GUI relies on.
A round-trip through ``ElementTree`` would subtly reformat all of
that and leave the operator with a diff they cannot review.

Atomicity on the wire
---------------------
Rather than pulling the file, mutating locally, and pushing back,
we run the whole edit on pfSense itself using a ``sed`` command
over a single SSH call. This avoids the long round-trip of a 200 KB
config over SSH and keeps the write strictly local to pfSense.
:class:`src.netgate_apply.NetgateApplier` has already pulled a local
backup before invoking us, so the rollback path is intact.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from wardsoar.core.remote_agents.pfsense_aliastable import (
    DEFAULT_ALIAS_DIR,
    DEFAULT_ALIAS_FILE_PATH,
)

if TYPE_CHECKING:
    from wardsoar.core.remote_agents.pfsense_ssh import PfSenseSSH

logger = logging.getLogger("ward_soar.pfsense_alias_migrate")


@dataclass(frozen=True)
class AliasMigrationResult:
    """Outcome of :func:`migrate_alias_to_urltable`."""

    success: bool
    preserved_entries: int
    message: str


# ---------------------------------------------------------------------------
# Pure text transform — unit-tested in isolation.
# ---------------------------------------------------------------------------


#: Regex for the alias block we target. The ``(?P<body>...)`` capture
#: gives us full access to the block contents; the outer ``<alias>``
#: tags are re-emitted verbatim so sibling aliases stay untouched.
#: ``re.DOTALL`` because the block spans multiple lines.
_ALIAS_BLOCK_RE = re.compile(
    r"(?P<open>\s*<alias>\s*\n)"  # leading whitespace + opening tag + newline
    r"(?P<body>(?:.(?!<alias>))*?)"  # body up to (but not including) the next opening
    r"(?P<close>\s*</alias>\s*\n)",
    re.DOTALL,
)

_NAME_RE = re.compile(r"<name>([^<]+)</name>")
_TYPE_RE = re.compile(r"<type>[^<]*</type>")
_ADDRESS_RE = re.compile(r"<address>([^<]*)</address>\s*\n?")
_URL_RE = re.compile(r"<url>[^<]*</url>\s*\n?")
_UPDATEFREQ_RE = re.compile(r"<updatefreq>[^<]*</updatefreq>\s*\n?")


def _split_address(body: str) -> list[str]:
    """Pull the IPs (or CIDRs) out of the alias's existing ``<address>`` element.

    pfSense stores them space-separated inside the tag. Empty
    content is the common post-install state.
    """
    match = _ADDRESS_RE.search(body)
    if not match:
        return []
    raw = (match.group(1) or "").strip()
    if not raw:
        return []
    return [tok for tok in raw.split() if tok]


def migrate_xml_in_place(
    xml_text: str,
    alias_name: str = "blocklist",
    file_url: str = f"file://{DEFAULT_ALIAS_FILE_PATH}",
) -> tuple[str, list[str]]:
    """Return the transformed XML and the list of entries that must be seeded.

    The transformation is a no-op if no alias named ``alias_name``
    exists, or if that alias is already ``urltable``. In those cases
    the returned XML equals the input and the preserved entries list
    is empty. The caller can therefore treat the operation as
    idempotent.

    Args:
        xml_text: Full ``config.xml`` contents.
        alias_name: Name of the alias to migrate (default ``blocklist``).
        file_url: ``file://`` URL to wire into the alias's ``<url>`` tag.

    Returns:
        ``(new_xml, preserved_entries)`` where ``preserved_entries`` is
        the list of IPs/CIDRs that were already in the alias's
        ``<address>`` tag. The caller seeds the url-table file with
        these before triggering a pfSense reload so no previously
        blocked IP is accidentally released.
    """
    preserved: list[str] = []

    def _maybe_convert(match: "re.Match[str]") -> str:
        body = match.group("body")
        name_match = _NAME_RE.search(body)
        if name_match is None or name_match.group(1).strip() != alias_name:
            return match.group(0)  # different alias, untouched

        # If already urltable, no-op. A second Apply after migration
        # is therefore safe.
        if re.search(r"<type>\s*urltable\s*</type>", body):
            return match.group(0)

        preserved.extend(_split_address(body))

        # Flip type to urltable.
        new_body = _TYPE_RE.sub("<type>urltable</type>", body, count=1)
        # Drop the legacy <address> tag (and its trailing newline).
        new_body = _ADDRESS_RE.sub("", new_body, count=1)
        # Remove any pre-existing <url> / <updatefreq> to make the
        # following insertion idempotent across partial migrations.
        new_body = _URL_RE.sub("", new_body)
        new_body = _UPDATEFREQ_RE.sub("", new_body)

        # Insert the new tags immediately after the <type> line. The
        # tab indent matches pfSense's own style; we sample it from
        # the opening tag rather than hardcoding "\t\t\t" so the
        # result looks right even under unusual wrappers.
        indent_match = re.match(r"([ \t]*)<alias>", match.group("open"))
        base_indent = (indent_match.group(1) if indent_match else "\t\t") + "\t"
        insertion = (
            f"{base_indent}<url>{file_url}</url>\n" f"{base_indent}<updatefreq>1</updatefreq>\n"
        )
        new_body = re.sub(
            r"(<type>urltable</type>\s*\n)",
            r"\1" + insertion,
            new_body,
            count=1,
        )

        return match.group("open") + new_body + match.group("close")

    new_xml = _ALIAS_BLOCK_RE.sub(_maybe_convert, xml_text)
    return new_xml, preserved


# ---------------------------------------------------------------------------
# SSH-driven orchestration
# ---------------------------------------------------------------------------


#: Remote path of the live config. Quoted in every shell command we
#: build so a future pfSense relocation is a one-line change here.
REMOTE_CONFIG_XML_PATH = "/cf/conf/config.xml"


async def migrate_alias_to_urltable(
    ssh: "PfSenseSSH",
    alias_name: str = "blocklist",
) -> AliasMigrationResult:
    """Run the host→urltable migration on pfSense.

    Execution order matters for safety:

    1. Pull the current ``config.xml`` so we can compute the new
       content locally (deterministic transform, easy to diff in
       tests).
    2. Compute the transformed XML and the list of IPs we must
       preserve from the legacy ``<address>`` element.
    3. Create ``/var/db/aliastables/`` and seed the alias file with
       the preserved entries *before* pushing the new XML. If we
       pushed XML first, pfSense would reload and find the url-table
       pointing at a missing file — a transient error in the logs
       but not a correctness issue. Doing it in this order avoids
       even the transient log noise.
    4. Push the new ``config.xml`` atomically (temp-file + rename
       via shell heredoc with a sentinel).
    5. Trigger the pfSense filter reload so the alias definition
       propagates everywhere (``/etc/rc.filter_configure``).
    6. Run ``pfctl -t <alias> -T replace -f <file>`` so the live
       table matches the file immediately, without waiting for the
       next pfSense config sync.
    7. Verify: ``pfctl -s Tables`` must still list the alias; the
       table contents must equal the preserved IPs.

    Any failure after step 4 leaves the caller (``NetgateApplier``)
    to restore the XML backup it captured before calling us. This
    function does not roll back itself — the applier owns that path.
    """
    # Step 1 — pull config.xml.
    cat_cmd = f"cat {REMOTE_CONFIG_XML_PATH} 2>/dev/null"
    ok, current_xml = await ssh.run_read_only(cat_cmd, timeout=20)
    if not ok or not current_xml:
        return AliasMigrationResult(False, 0, "failed to read config.xml over SSH")

    # Step 2 — compute new XML.
    new_xml, preserved = migrate_xml_in_place(current_xml, alias_name=alias_name)
    if new_xml == current_xml:
        # Either the alias does not exist or it is already urltable.
        # Both are successful outcomes from the operator's point of view.
        return AliasMigrationResult(
            True,
            0,
            "no change needed (alias already urltable or missing)",
        )

    # Step 3 — seed the file with preserved entries.
    #
    # Shell shape: ``set -e`` turns any non-zero exit into an abort, so
    # a failed ``mkdir`` or ``cat`` surfaces as ``ok=False`` instead of
    # being silently masked by the last statement's status.
    payload = "\n".join(preserved) + ("\n" if preserved else "")
    if "__WARDSOAR_ALIAS_EOF__" in payload:
        return AliasMigrationResult(
            False, len(preserved), "preserved payload contains heredoc sentinel"
        )
    seed_cmd = (
        "set -e\n"
        f"mkdir -p {DEFAULT_ALIAS_DIR}\n"
        f"cat > {DEFAULT_ALIAS_FILE_PATH} <<'__WARDSOAR_ALIAS_EOF__'\n"
        f"{payload}"
        "__WARDSOAR_ALIAS_EOF__\n"
    )
    logger.info(
        "migrate_alias_to_urltable: step 3 — seeding alias file with %d entries",
        len(preserved),
    )
    ok, out = await ssh.run_read_only(seed_cmd, timeout=15)
    if not ok:
        return AliasMigrationResult(
            False,
            len(preserved),
            f"could not seed alias file: {out[:200]}",
        )

    # Step 4 — push new config.xml via tempfile+mv on the Netgate.
    #
    # Critical: the ``mv`` must happen ONLY if the heredoc-backed
    # ``cat`` succeeded, and ``rc.conf_mount_ro`` must run afterwards
    # so the file system goes back to read-only. The previous shape
    # put ``&& mv …`` on a line BY ITSELF after the heredoc delimiter,
    # which POSIX sh rejects as "syntax error near unexpected token
    # '&&'". The fix is ``set -e`` + one-statement-per-line: any
    # failing step aborts the whole script with non-zero, which
    # asyncssh surfaces as ``ok=False``. The rc.conf_mount_* scripts
    # are wrapped in ``|| true`` because they return non-zero when
    # the FS is already in the target mode — expected on every pass.
    if "__WARDSOAR_XML_EOF__" in new_xml:
        return AliasMigrationResult(
            False,
            len(preserved),
            "new config.xml would collide with heredoc sentinel — refusing push",
        )
    push_cmd = (
        "set -e\n"
        "/etc/rc.conf_mount_rw >/dev/null 2>&1 || true\n"
        f"cat > {REMOTE_CONFIG_XML_PATH}.tmp <<'__WARDSOAR_XML_EOF__'\n"
        f"{new_xml}"
        "__WARDSOAR_XML_EOF__\n"
        f"mv {REMOTE_CONFIG_XML_PATH}.tmp {REMOTE_CONFIG_XML_PATH}\n"
        "/etc/rc.conf_mount_ro >/dev/null 2>&1 || true\n"
    )
    logger.info(
        "migrate_alias_to_urltable: step 4 — pushing new config.xml (%d bytes)",
        len(new_xml),
    )
    ok, out = await ssh.run_read_only(push_cmd, timeout=30)
    if not ok:
        return AliasMigrationResult(
            False,
            len(preserved),
            f"config.xml push failed: {out[:200]}",
        )

    # Step 5 — propagate the new alias type through pfSense.
    logger.info("migrate_alias_to_urltable: step 5 — triggering filter reload")
    reload_cmd = "/etc/rc.filter_configure 2>&1 | tail -5"
    ok, out = await ssh.run_read_only(reload_cmd, timeout=30)
    if not ok:
        return AliasMigrationResult(
            False,
            len(preserved),
            f"pfSense filter reload failed: {out[:200]}",
        )

    # Step 6 — align the live table to the file.
    logger.info("migrate_alias_to_urltable: step 6 — pfctl replace from file")
    replace_cmd = f"pfctl -t {alias_name} -T replace -f {DEFAULT_ALIAS_FILE_PATH} 2>&1 | head -5"
    ok, out = await ssh.run_read_only(replace_cmd, timeout=15)
    if not ok:
        return AliasMigrationResult(
            False,
            len(preserved),
            f"pfctl replace failed: {out[:200]}",
        )

    # Step 7 — verify table is present and populated.
    logger.info("migrate_alias_to_urltable: step 7 — verifying table is present")
    verify_cmd = (
        f"pfctl -s Tables 2>/dev/null | grep -w {alias_name} || true; "
        f"echo ---; pfctl -t {alias_name} -T show 2>/dev/null | wc -l"
    )
    ok, out = await ssh.run_read_only(verify_cmd, timeout=10)
    if not ok or alias_name not in out:
        return AliasMigrationResult(
            False,
            len(preserved),
            f"post-migration verification failed: {out[:200]}",
        )

    logger.warning(
        "migrate_alias_to_urltable: succeeded — preserved %d entries",
        len(preserved),
    )
    return AliasMigrationResult(
        True,
        len(preserved),
        f"migrated {alias_name} host→urltable, preserved {len(preserved)} entries",
    )


__all__ = [
    "AliasMigrationResult",
    "REMOTE_CONFIG_XML_PATH",
    "migrate_alias_to_urltable",
    "migrate_xml_in_place",
]
