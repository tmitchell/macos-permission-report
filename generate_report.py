#!/usr/bin/env python3
"""
macOS Privacy Permission Audit — Report Generator

Queries the macOS TCC (Transparency, Consent, and Control) databases, identifies
which applications hold dangerous privacy permissions, flags ghost entries for
uninstalled apps, and generates a detailed HTML report.

Usage:
    uv run generate_report.py [--output PATH]

TCC Background
--------------
macOS gatekeeps sensitive resources (camera, mic, files, etc.) through TCC.
Each permission grant is stored as a row in a SQLite database.

There are two TCC databases:

  User-level — ~/Library/Application Support/com.apple.TCC/TCC.db
    Stores: Camera, Microphone, Contacts, Calendar, Reminders, Bluetooth,
            Apple Events (Automation), Media Library, Photos, folder access
            (Desktop, Documents, Downloads), iCloud Drive, etc.

  System-level — /Library/Application Support/com.apple.TCC/TCC.db
    Stores: Full Disk Access, Accessibility, Screen Recording,
            Input Monitoring, Developer Tools.
    ⚠️  Requires Full Disk Access to read.  Running from Terminal (which has
        FDA) works; running from an IDE may not unless the IDE also has FDA.

The key table is `access`, with these columns:
    service              — TCC service ID, e.g. "kTCCServiceCamera"
    client               — bundle ID (e.g. "com.brave.Browser") or absolute path
    client_type          — 0 = bundle identifier, 1 = absolute path
    auth_value           — 0 = denied, 2 = allowed, 3 = limited
    auth_reason          — why it was set (2 = user, 3 = AppleEvents, 4 = system, 5 = system policy)
    indirect_object_identifier — for Automation: the target app's bundle ID
"""

from __future__ import annotations

import argparse
import os
import plistlib
import platform
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

# ═══════════════════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════════════════

TCC_USER_DB = Path.home() / "Library/Application Support/com.apple.TCC/TCC.db"
TCC_SYSTEM_DB = Path("/Library/Application Support/com.apple.TCC/TCC.db")

AUTH_DENIED = 0
AUTH_ALLOWED = 2
AUTH_LIMITED = 3

# Human-friendly names for TCC services used in the "Personal Data" and
# "Automation" tables where a single section covers multiple services.
SERVICE_FRIENDLY = {
    "kTCCServiceAddressBook": "Contacts",
    "kTCCServiceCalendar": "Calendar",
    "kTCCServiceReminders": "Reminders",
    "kTCCServiceBluetoothAlways": "Bluetooth",
    "kTCCServiceListenEvent": "Listen",
    "kTCCServicePostEvent": "Post",
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Permission Category Definitions
# ═══════════════════════════════════════════════════════════════════════════════
#
# Each category maps to one or more TCC services.  The "source" field indicates
# which database holds these entries.
#
# Threat descriptions are shown in the report to explain the real-world impact
# of each permission category.

CATEGORIES = [
    {
        "id": "fda",
        "services": ["kTCCServiceSystemPolicyAllFiles"],
        "source": "system",
        "name": "Full Disk Access",
        "icon": "&#128274;",
        "risk_level": "critical",
        "subtitle": "can read all user & system data",
        "what_it_does": (
            "Grants unrestricted read/write access to <strong>every file</strong> on "
            "the system — emails, photos, browser data, SSH keys, documents, and "
            "application databases. This bypasses all file-level privacy restrictions."
        ),
        "if_malicious": (
            "Could silently copy your entire digital life: passwords stored by browsers, "
            "private SSH and GPG keys, tax and medical documents, every photo you have, "
            "all chat histories. Could also modify or delete files, plant backdoors, or "
            "alter system configurations."
        ),
    },
    {
        "id": "accessibility",
        "services": ["kTCCServiceAccessibility"],
        "source": "system",
        "name": "Accessibility",
        "icon": "&#9995;",
        "risk_level": "critical",
        "subtitle": "can control your computer, simulate input",
        "what_it_does": (
            "Allows the app to observe and control your computer through the Accessibility "
            "API. This includes <strong>reading text from any window</strong>, simulating "
            "mouse clicks and keystrokes, and manipulating any application's UI."
        ),
        "if_malicious": (
            "Could act as a complete keylogger, read passwords as you type them, click "
            "buttons in banking apps, compose and send emails on your behalf, accept "
            "security prompts automatically, or silently puppet any application."
        ),
    },
    {
        "id": "screen_recording",
        "services": ["kTCCServiceScreenCapture"],
        "source": "system",
        "name": "Screen Recording",
        "icon": "&#128247;",
        "risk_level": "critical",
        "subtitle": "can capture everything visible on screen",
        "what_it_does": (
            "Allows continuous capture of <strong>everything visible on screen</strong> — "
            "all windows, all desktops, including passwords, private messages, financial "
            "data, and medical information as they are displayed."
        ),
        "if_malicious": (
            "Could record your entire screen session 24/7, capturing passwords as they "
            "briefly appear, private conversations, financial account balances, confidential "
            "documents — anything that is ever visible on your display."
        ),
    },
    {
        "id": "input_monitoring",
        "services": ["kTCCServiceListenEvent", "kTCCServicePostEvent"],
        "source": "system",
        "name": "Input Monitoring",
        "icon": "&#9000;",
        "risk_level": "critical",
        "subtitle": "can observe keystrokes and mouse events",
        "extra_columns": [{"key": "subtype", "header": "Type"}],
        "what_it_does": (
            "Can observe <strong>all keyboard and mouse input</strong> at the system level, "
            "before it reaches any application. <em>Listen</em> mode passively reads events; "
            "<em>Post</em> mode can also generate synthetic keystrokes and clicks."
        ),
        "if_malicious": (
            "This is the textbook keylogger permission. Could record every password, credit "
            "card number, private message, and search query you type. <em>Post</em> mode "
            "could also inject fake keystrokes or mouse clicks into any application."
        ),
    },
    {
        "id": "camera",
        "services": ["kTCCServiceCamera"],
        "source": "user",
        "name": "Camera",
        "icon": "&#127909;",
        "risk_level": "high",
        "subtitle": "can capture photos and video of you",
        "what_it_does": (
            "Can access the built-in or connected camera to capture photos and video. macOS "
            "activates the <strong>green indicator LED</strong> when the camera is in use, "
            "but the app controls when and how long it records."
        ),
        "if_malicious": (
            "Could photograph or record video of you and your surroundings whenever the app "
            "is running. The green LED will illuminate, but a brief capture can easily go "
            "unnoticed, especially if timed during other camera use."
        ),
    },
    {
        "id": "microphone",
        "services": ["kTCCServiceMicrophone"],
        "source": "user",
        "name": "Microphone",
        "icon": "&#127908;",
        "risk_level": "high",
        "subtitle": "can record audio from your environment",
        "what_it_does": (
            "Can access the built-in or connected microphone to capture audio. macOS shows "
            "an <strong>orange indicator dot</strong> in the menu bar when the mic is active."
        ),
        "if_malicious": (
            "Could record all ambient audio — conversations, phone calls, meetings — "
            "whenever the app is running. The orange dot appears but is easily overlooked, "
            "and brief recordings may not be noticed at all."
        ),
    },
    {
        "id": "personal_data",
        "services": [
            "kTCCServiceAddressBook",
            "kTCCServiceCalendar",
            "kTCCServiceReminders",
            "kTCCServiceBluetoothAlways",
        ],
        "source": "user",
        "name": "Personal Data Access",
        "icon": "&#128209;",
        "risk_level": "medium",
        "subtitle": "Contacts, Calendar, Reminders, Bluetooth",
        "extra_columns": [{"key": "subtype", "header": "Permission"}],
        "what_it_does": (
            "Grants access to personal information stores: your <strong>Contacts</strong> "
            "(names, phone numbers, addresses), <strong>Calendar</strong> (events, locations, "
            "attendees), <strong>Reminders</strong>, and <strong>Bluetooth</strong> (nearby "
            "device discovery and pairing)."
        ),
        "if_malicious": (
            "Contacts could be harvested for spam or phishing. Calendar data reveals your "
            "daily schedule, travel plans, and meeting attendees — ideal for social "
            "engineering. Bluetooth access allows tracking nearby devices to fingerprint "
            "your location."
        ),
    },
    {
        "id": "automation",
        "services": ["kTCCServiceAppleEvents"],
        "source": "user",
        "name": "Automation (Apple Events)",
        "icon": "&#9881;",
        "risk_level": "medium",
        "subtitle": "can control other applications",
        "extra_columns": [{"key": "subtype", "header": "Can Control"}],
        "what_it_does": (
            "Can send Apple Events to <strong>control specific other applications</strong> — "
            "clicking buttons, reading data, executing menu commands — as if it were the "
            "user sitting at the keyboard."
        ),
        "if_malicious": (
            "Could use target applications as proxies: sending emails through Mail, reading "
            "files through Finder, executing shell commands through Terminal, or piggybacking "
            "on another app's broader permissions."
        ),
    },
]

# Build a lookup: service → category id
_SERVICE_TO_CATEGORY = {}
for _cat in CATEGORIES:
    for _svc in _cat["services"]:
        _SERVICE_TO_CATEGORY[_svc] = _cat["id"]


# ═══════════════════════════════════════════════════════════════════════════════
#  Invasive Software Definitions
# ═══════════════════════════════════════════════════════════════════════════════
#
# Apps that are invasive *by design*.  These get a red alert banner at the top
# of the report.

INVASIVE_APPS = {
    "com.Respondus.LockDownBrowser": {
        "name": "LockDown Browser",
        "type": "Exam Proctoring Spyware",
        "description": (
            "Respondus LockDown Browser is exam proctoring software that locks down your "
            "computer and monitors you via camera, microphone, and screen capture during "
            "tests. While required by some institutions, it functions as surveillance "
            "software — recording video of your face, audio from your room, and "
            "screenshots of your desktop. These permissions should be revoked between "
            "exam sessions."
        ),
        "concern_reason": (
            "Exam proctoring software. Records your camera, microphone, and screen — "
            "the full surveillance trifecta. Invasive by design, not by accident."
        ),
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
#  App Assessment Knowledge Base
# ═══════════════════════════════════════════════════════════════════════════════
#
# For each known app, maps TCC services to an (assessment, tooltip_reason) pair.
#   assessment: "ok"       → badge shows "Expected"
#                "moderate" → badge shows "Review"
#                "concern"  → badge shows "Invasive"
#
#   "_default" is used when no service-specific rule exists.
#   "_name" overrides the display name if needed.
#
# Apps not in this database get a default assessment based on the service's
# risk level.

ASSESSMENTS: dict[str, dict] = {
    # ── Apple system tools ────────────────────────────────────────────
    "com.apple.Terminal": {
        "_default": ("ok", "Apple system shell. All permissions are standard for a terminal environment."),
    },
    "com.apple.shortcuts": {
        "_default": ("ok", "Apple's built-in automation app; permissions are system-granted."),
    },

    # ── Launchers & system utilities ──────────────────────────────────
    "com.runningwithcrayons.Alfred": {
        "kTCCServiceSystemPolicyAllFiles": ("ok", "File-search launcher requires full filesystem indexing to deliver instant results."),
        "kTCCServiceAccessibility": ("ok", "Global hotkeys, snippet expansion, and clipboard history require the Accessibility API."),
        "kTCCServiceAddressBook": ("ok", "Contact search feature lets you look up people from the launcher bar."),
        "kTCCServiceAppleEvents": ("ok", "Alfred workflows control Terminal, Finder, and Shortcuts via Apple Events."),
        "_default": ("ok", "Alfred is a power-user launcher whose core features require broad system access."),
    },
    "com.sindresorhus.Supercharge": {
        "_default": ("ok", "Sindre Sorhus system-automation suite. Broad access is core to its function as a macOS enhancer."),
    },

    # ── Window / input management ─────────────────────────────────────
    "co.highlyopinionated.swish": {
        "_default": ("ok", "Window manager driven by trackpad gestures — must intercept input events to detect swipes."),
    },
    "com.caldis.Mos": {
        "_default": ("ok", "Mouse scroll-smoothing and direction-reversal tool — must intercept scroll events via Accessibility."),
    },
    "jp.plentycom.app.SteerMouse": {
        "_default": ("ok", "Mouse button and cursor customization tool — requires Accessibility to remap hardware input."),
    },
    "com.if.Amphetamine": {
        "kTCCServiceAccessibility": ("ok", "Uses Accessibility for closed-display mode and app-based trigger features."),
        "kTCCServiceBluetoothAlways": ("ok", "Bluetooth proximity triggers let it keep the Mac awake while a specific device is nearby."),
        "_default": ("ok", "Sleep-prevention utility with trigger-based automation features."),
    },

    # ── Screenshot / recording ────────────────────────────────────────
    "pl.maketheweb.cleanshotx": {
        "kTCCServiceScreenCapture": ("ok", "Screenshot and screen-recording tool. Screen capture is its entire purpose."),
        "kTCCServiceListenEvent": ("ok", "Monitors global keyboard shortcuts to trigger screenshot capture."),
        "kTCCServiceMicrophone": ("ok", "Records microphone audio during screen recordings when the user enables it."),
        "_default": ("ok", "CleanShot X is a screenshot/recording utility; these permissions are core functionality."),
    },
    "com.obsproject.obs-studio": {
        "_name": "OBS Studio",
        "_default": ("ok", "Open-source video recorder and live streamer. Camera, microphone, and screen capture are its entire purpose."),
    },

    # ── Browsers ──────────────────────────────────────────────────────
    "com.brave.Browser": {
        "_default": ("ok", "Web browser. Camera, mic, and screen sharing are needed for web-based video calls (Meet, Zoom, etc.)."),
    },

    # ── Communication ─────────────────────────────────────────────────
    "com.microsoft.teams2": {
        "kTCCServiceBluetoothAlways": ("ok", "Detects Bluetooth headsets and routes audio for calls."),
        "_default": ("ok", "Video-conferencing app. Camera, mic, and screen sharing are needed for meetings."),
    },
    "dev.vencord.vesktop": {
        "kTCCServiceAppleEvents": ("ok", "Controls the Music app to show 'Now Playing' as Discord Rich Presence status."),
        "_default": ("ok", "Discord client. Camera, mic, and screen sharing are used for voice/video calls."),
    },
    "us.zoom.xos": {
        "_name": "Zoom",
        "kTCCServiceCamera": ("ok", "Video meetings — the headline feature."),
        "kTCCServiceMicrophone": ("ok", "Voice for meetings."),
        "kTCCServiceScreenCapture": ("ok", "Screen-share during meetings."),
        "kTCCServiceSystemPolicyAllFiles": (
            "moderate",
            "Zoom does not need Full Disk Access to function. If granted, revoke.",
        ),
        "_default": ("ok", "Video-conferencing app. Camera, mic, and screen sharing are core features."),
    },

    # ── AI assistants ─────────────────────────────────────────────────
    "com.anthropic.claudefordesktop": {
        "kTCCServiceSystemPolicyAllFiles": (
            "moderate",
            "MCP servers and file-editing tools need filesystem access, but FDA grants "
            "visibility over all data on disk — well beyond what most tasks require.",
        ),
        "kTCCServiceAccessibility": (
            "moderate",
            "Enables the computer-use feature. Grants an AI model the ability to observe "
            "and manipulate your UI.",
        ),
        "kTCCServiceScreenCapture": (
            "moderate",
            "Computer-use reads screen content, letting the AI see everything visible — "
            "including passwords, DMs, and financial data on screen.",
        ),
        "kTCCServiceMicrophone": (
            "moderate",
            "Voice-input feature. Grants ambient audio access to an AI assistant process.",
        ),
        "_default": (
            "moderate",
            "Each permission serves a real feature (MCP tools, computer use, voice input), "
            "but combined they give an AI model near-total system access.",
        ),
    },

    # ── IDEs & editors ────────────────────────────────────────────────
    "com.jetbrains.PhpStorm": {
        "_default": ("ok", "IDE needs broad filesystem access for project files, dependencies, and tool integrations."),
    },
    "com.sublimetext.4": {
        "_default": ("ok", "Text editor. Automation (Finder) is used for 'Reveal in Finder' and file-open dialogs."),
    },

    # ── Disk / cleanup tools ──────────────────────────────────────────
    "com.daisydiskapp.DaisyDisk": {
        "_default": ("ok", "Disk usage analyzer. Must scan every file to calculate and display storage consumption."),
    },
    "com.macpaw.CleanMyMac5": {
        "kTCCServiceBluetoothAlways": (
            "moderate",
            "A system cleaner has no obvious need for Bluetooth access. This may be telemetry "
            "or a peripheral-detection feature, but the purpose is unclear.",
        ),
        "_default": ("ok", "System cleaner and optimizer. Scanning caches, logs, and app remnants requires broad file access."),
    },
    "com.alienator88.Pearcleaner": {
        "_default": ("ok", "App uninstaller. Must traverse the entire filesystem to find leftover files after app removal."),
    },

    # ── Notes & writing ───────────────────────────────────────────────
    "md.obsidian": {
        "kTCCServiceSystemPolicyAllFiles": (
            "moderate",
            "A note-taking app could function with vault-scoped folder access instead of "
            "Full Disk Access. FDA is broader than what Markdown editing requires.",
        ),
        "_default": ("ok", "Obsidian's note-taking features."),
    },

    # ── Utilities ─────────────────────────────────────────────────────
    "com.Replacicon.Replacicon": {
        "kTCCServiceSystemPolicyAllFiles": (
            "moderate",
            "Needs to modify app bundles in /Applications to replace icons, but FDA is "
            "broader than what icon replacement requires.",
        ),
    },
    "com.sindresorhus.Camera-Preview": {
        "_default": ("ok", "Camera preview utility. Showing your camera feed is its sole purpose."),
    },
    "codes.rambo.AirBuddy": {
        "_default": ("ok", "Bluetooth device manager. Managing AirPods and other BT accessories is its core function."),
    },

    # ── Email & calendar ──────────────────────────────────────────────
    "com.flexibits.fantastical2.mac": {
        "_default": ("ok", "Full-featured calendar app. Contacts, Calendar, and Reminders access are needed for invites, scheduling, and task sync."),
    },
    "com.mimestream.Mimestream": {
        "_default": ("ok", "Email client. Contacts for autocomplete and Calendar for event display are standard email features."),
    },
    "com.culturedcode.ThingsMac": {
        "_default": ("ok", "Task manager. Calendar access shows events alongside tasks; Automation sends events to Calendar."),
    },

    # ── Media ─────────────────────────────────────────────────────────
    "design.yugen.Flow": {
        "_default": ("ok", "Pomodoro timer app. Safari automation is used for focus-related browser features."),
    },

    # ── File transfer ─────────────────────────────────────────────────
    "com.panic.Transmit": {
        "_default": ("ok", "FTP/SFTP client. Folder access is needed to upload and download files."),
    },

    # ── Remote access ─────────────────────────────────────────────────
    "com.teamviewer.TeamViewer": {
        "_default": (
            "ok",
            "Remote-control software. Accessibility, Screen Recording, Input Monitoring, "
            "and Full Disk Access are required for remote control to function — but these "
            "permissions should be revoked when the app is not in active use.",
        ),
    },
    "com.philandro.anydesk": {
        "_name": "AnyDesk",
        "_default": ("ok", "Same remote-control profile as TeamViewer; revoke permissions when not in active use."),
    },
    "com.carriez.rustdesk": {
        "_name": "RustDesk",
        "_default": ("ok", "Open-source remote-control alternative. Same permission profile as TeamViewer."),
    },

    # ── VPN ───────────────────────────────────────────────────────────
    "com.nordvpn.NordVPN": {
        "_default": ("ok", "VPN client. System-level networking permissions are required to install the network extension."),
    },

    # ── Password managers ─────────────────────────────────────────────
    "com.1password.1password": {
        "_name": "1Password",
        "kTCCServiceAccessibility": ("ok", "Auto-fill across native macOS apps requires Accessibility to detect form fields."),
        "_default": ("ok", "Password manager. Accessibility for autofill is its primary integration point on macOS."),
    },

    # ── Exam proctoring — handled by INVASIVE_APPS ────────────────────
    # com.Respondus.LockDownBrowser is defined in INVASIVE_APPS above.
}

# Human-friendly names for uninstalled (ghost) apps whose bundle IDs
# would otherwise resolve to unhelpful fragments like "cp-dev-mgr".
GHOST_NAMES: dict[str, str] = {
    "com.logi.cp-dev-mgr": "Logi CP Dev Manager",
    "com.logi.optionsplus": "Logi Options+",
    "com.surteesstudios.Bartender": "Bartender",
    "com.hnc.Discord": "Discord",
    "com.sindresorhus.Command-X": "Command X",
    "com.sindresorhus.Text-Lens": "Text Lens",
    "cools.wins.main": "Wins",
    "com.pilotmoon.scroll-reverser": "Scroll Reverser",
    "net.matthewpalmer.Rocket": "Rocket",
    "dk.FIrstForm.DockFix": "DockFix",
    "com.davidbures.cork": "Cork",
    "com.luna.obsidianopener": "Obsidian Opener",
    "com.jetbrains.CLion": "CLion",
    "com.jetbrains.rider": "Rider",
    "com.reincubate.macos.cam": "Camo",
    "com.google.drivefs": "Google Drive",
    "com.google.Chrome": "Google Chrome",
    "com.BZG.unite": "Unite",
    "com.adobe.PremierePro.25": "Adobe Premiere Pro",
    "org.mozilla.thunderbird": "Thunderbird",
    "codes.rambo.AirBuddyHelper": "AirBuddy Helper",
    "jp.plentycom.boa.SteerMouse": "SteerMouse Manager",
}

# Helper bundle IDs that belong to an installed parent app.
# These are filtered from the ghost list because their parent IS installed.
KNOWN_HELPERS: dict[str, str] = {
    "codes.rambo.AirBuddyHelper": "codes.rambo.AirBuddy",
    "jp.plentycom.boa.SteerMouse": "jp.plentycom.app.SteerMouse",
    "codes.rambo.AirBuddyHelper.AirBuddyWidgetKit": "codes.rambo.AirBuddy",
    "85C27NK92C.com.flexibits.fantastical2.mac.helper": "com.flexibits.fantastical2.mac",
}

# Path-based entry assessments — keyed by a substring of the path
PATH_ASSESSMENTS: dict[str, dict] = {
    "node": {
        "_name": "node",
        "kTCCServiceAccessibility": (
            "moderate",
            "The Node.js runtime itself has Accessibility access. Every script you run "
            "via this binary inherits it — including npm packages and one-off scripts.",
        ),
        "kTCCServicePostEvent": (
            "moderate",
            "Can synthesize keyboard and mouse events. Any Node.js script run through "
            "this binary can inject input into other applications.",
        ),
        "kTCCServiceAppleEvents": (
            "moderate",
            "Can control Safari, Finder, and System Events. Any script inherits this.",
        ),
        "_default": (
            "moderate",
            "Permissions granted to a runtime binary are inherited by every script it "
            "executes — this is a wide implicit trust surface.",
        ),
    },
    "uv": {
        "_name": "uv / uvx",
        "kTCCServiceSystemPolicyAllFiles": (
            "moderate",
            "Python package manager with Full Disk Access across multiple path variants. "
            "Likely granted to unblock a one-time install; broader than routine use requires.",
        ),
        "_default": ("moderate", "CLI tool with unusually broad permissions for a package manager."),
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
#  Data Types
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class InstalledApp:
    name: str
    bundle_id: str
    path: str

@dataclass
class PermissionGrant:
    service: str
    client: str          # bundle ID or path
    client_type: int     # 0 = bundle ID, 1 = path
    auth_value: int
    source: str          # "user" or "system"
    target: str = ""     # for Automation: target app's bundle ID
    app_name: str = ""
    is_installed: bool = True
    assessment: str = "moderate"
    assessment_label: str = "Review"
    assessment_reason: str = ""
    notes: str = ""
    extra: dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
#  TCC Database Queries
# ═══════════════════════════════════════════════════════════════════════════════

def query_tcc_database(db_path: Path, source_label: str) -> list[dict]:
    """
    Read all rows from a TCC database's `access` table.

    Opens the database in read-only mode via SQLite URI to avoid any risk of
    accidental writes.  Returns a list of dicts with the key columns.

    The `access` table schema (macOS 26 / Tahoe):
        service              TEXT    — e.g. "kTCCServiceCamera"
        client               TEXT    — bundle ID or absolute path
        client_type          INTEGER — 0 = bundle ID, 1 = absolute path
        auth_value           INTEGER — 0 = denied, 2 = allowed, 3 = limited
        auth_reason          INTEGER — how the permission was set
        indirect_object_identifier TEXT — for AppleEvents: the target app

    Parameters
    ----------
    db_path : Path
        Filesystem path to the TCC.db file.
    source_label : str
        "user" or "system" — tagged onto each returned row.

    Returns
    -------
    list[dict]
        One dict per row, or an empty list if the database is unreadable.
    """
    if not db_path.exists():
        print(f"  ⚠ {db_path} not found")
        return []

    try:
        # Open read-only via URI.  The system TCC database may be protected
        # by SIP/TCC itself; access denial surfaces as OperationalError or,
        # on older Python/SQLite builds, its parent DatabaseError.
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT service, client, client_type, auth_value, auth_reason, "
            "       indirect_object_identifier "
            "FROM access"
        )
        rows = [
            {
                "service": row["service"],
                "client": row["client"],
                "client_type": row["client_type"],
                "auth_value": row["auth_value"],
                "auth_reason": row["auth_reason"],
                "target": row["indirect_object_identifier"] or "",
                "source": source_label,
            }
            for row in cursor
        ]
        conn.close()
        return rows
    except sqlite3.DatabaseError as e:
        print(f"  ⚠ Cannot read {db_path}: {e}")
        print(f"    (The process may need Full Disk Access to read the {source_label} TCC database.)")
        return []


# ═══════════════════════════════════════════════════════════════════════════════
#  App Discovery
# ═══════════════════════════════════════════════════════════════════════════════

def read_bundle_id(app_path: Path) -> str | None:
    """
    Read CFBundleIdentifier from an .app bundle's Info.plist.

    Uses Python's built-in plistlib, which handles both XML and binary plists
    without shelling out to PlistBuddy or `defaults`.
    """
    info_plist = app_path / "Contents" / "Info.plist"
    if not info_plist.exists():
        return None
    try:
        with open(info_plist, "rb") as f:
            plist = plistlib.load(f)
            return plist.get("CFBundleIdentifier")
    except Exception:
        return None


def discover_installed_apps() -> dict[str, InstalledApp]:
    """
    Build a mapping of bundle ID → InstalledApp for every .app on the system.

    Uses Spotlight (`mdfind`) to efficiently locate all application bundles,
    then reads each bundle's Info.plist to extract its CFBundleIdentifier.

    Spotlight is preferred over manual directory traversal because it:
      - Handles apps nested inside other bundles (e.g. Xcode sub-apps)
      - Is fast even across large /Applications trees
      - Knows about apps in non-standard locations if indexed
    """
    search_dirs = [
        "/Applications",
        str(Path.home() / "Applications"),
        "/System/Applications",
    ]

    cmd = ["mdfind", "kMDItemContentType == 'com.apple.application-bundle'"]
    for d in search_dirs:
        cmd += ["-onlyin", d]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("  ⚠ mdfind failed; falling back to directory scan")
        return _discover_apps_fallback()

    apps: dict[str, InstalledApp] = {}
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        app_path = Path(line)
        bundle_id = read_bundle_id(app_path)
        if bundle_id and bundle_id not in apps:
            apps[bundle_id] = InstalledApp(
                name=app_path.stem,
                bundle_id=bundle_id,
                path=str(app_path),
            )
    return apps


def _discover_apps_fallback() -> dict[str, InstalledApp]:
    """Fallback: glob /Applications and ~/Applications for .app bundles."""
    apps: dict[str, InstalledApp] = {}
    for base in [Path("/Applications"), Path.home() / "Applications", Path("/System/Applications")]:
        if not base.exists():
            continue
        for app_path in base.glob("*.app"):
            bundle_id = read_bundle_id(app_path)
            if bundle_id and bundle_id not in apps:
                apps[bundle_id] = InstalledApp(
                    name=app_path.stem, bundle_id=bundle_id, path=str(app_path)
                )
    return apps


# ═══════════════════════════════════════════════════════════════════════════════
#  Assessment Logic
# ═══════════════════════════════════════════════════════════════════════════════

ASSESSMENT_LABELS = {"ok": "Expected", "moderate": "Review", "concern": "Invasive"}


def _match_path_key(path: str) -> str | None:
    """Find the PATH_ASSESSMENTS key that matches a binary path."""
    basename = os.path.basename(path)
    for key in PATH_ASSESSMENTS:
        if key in basename or key in path:
            return key
    return None


def get_assessment(client: str, client_type: int, service: str) -> tuple[str, str, str]:
    """
    Look up the assessment for a given app + permission combination.

    Returns (assessment, label, tooltip_reason).

    Resolution order:
      1. INVASIVE_APPS — always overrides
      2. ASSESSMENTS[bundle_id][service] — per-service rule
      3. ASSESSMENTS[bundle_id]["_default"] — app-level fallback
      4. PATH_ASSESSMENTS (for path-based entries)
      5. Generic defaults based on service risk level
    """
    # 1. Invasive apps
    if client in INVASIVE_APPS:
        reason = INVASIVE_APPS[client]["concern_reason"]
        return ("concern", "Invasive", reason)

    # 2–3. Bundle-ID based assessments
    if client_type == 0 and client in ASSESSMENTS:
        rules = ASSESSMENTS[client]
        if service in rules:
            a, r = rules[service]
            return (a, ASSESSMENT_LABELS[a], r)
        if "_default" in rules:
            a, r = rules["_default"]
            return (a, ASSESSMENT_LABELS[a], r)

    # 4. Path-based assessments
    if client_type == 1:
        key = _match_path_key(client)
        if key and key in PATH_ASSESSMENTS:
            rules = PATH_ASSESSMENTS[key]
            if service in rules:
                a, r = rules[service]
                return (a, ASSESSMENT_LABELS[a], r)
            if "_default" in rules:
                a, r = rules["_default"]
                return (a, ASSESSMENT_LABELS[a], r)

    # 5. Generic defaults
    critical_services = {
        "kTCCServiceSystemPolicyAllFiles",
        "kTCCServiceAccessibility",
        "kTCCServiceScreenCapture",
        "kTCCServiceListenEvent",
        "kTCCServicePostEvent",
    }
    if service in critical_services:
        return (
            "moderate", "Review",
            "No specific assessment on file for this app. This is a high-risk permission — verify it's still needed."
        )
    return (
        "ok", "Expected",
        "This permission appears standard for the app's category."
    )


def friendly_name(client: str, client_type: int, installed_apps: dict[str, InstalledApp]) -> str:
    """Resolve a TCC client to a human-friendly app name."""
    if client_type == 0:
        # Bundle ID — check installed apps, then assessments, then ghost names
        if client in installed_apps:
            return installed_apps[client].name
        if client in ASSESSMENTS and "_name" in ASSESSMENTS[client]:
            return ASSESSMENTS[client]["_name"]
        if client in INVASIVE_APPS:
            return INVASIVE_APPS[client]["name"]
        if client in GHOST_NAMES:
            return GHOST_NAMES[client]
        # Use the last component of the bundle ID
        return client.rsplit(".", 1)[-1]
    else:
        # Path-based — check PATH_ASSESSMENTS for friendly name
        key = _match_path_key(client)
        if key and "_name" in PATH_ASSESSMENTS.get(key, {}):
            return PATH_ASSESSMENTS[key]["_name"]
        basename = os.path.basename(client)
        # For nvm node, include version
        if "node" in client and ".nvm" in client:
            for part in client.split("/"):
                if part.startswith("v") and "." in part:
                    return f"node ({part})"
        return basename


# ═══════════════════════════════════════════════════════════════════════════════
#  Report Data Builder
# ═══════════════════════════════════════════════════════════════════════════════

def get_system_info() -> dict:
    """Gather macOS version info for the report header."""
    try:
        result = subprocess.run(["sw_vers"], capture_output=True, text=True, timeout=5)
        info = {}
        for line in result.stdout.strip().split("\n"):
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
        return {
            "product_name": info.get("ProductName", "macOS"),
            "product_version": info.get("ProductVersion", "Unknown"),
            "build_version": info.get("BuildVersion", ""),
            "arch": platform.machine(),
        }
    except Exception:
        return {"product_name": "macOS", "product_version": "Unknown", "build_version": "", "arch": ""}


def build_report_data() -> dict:
    """
    Orchestrate the full audit: query databases, discover apps, classify
    grants, and assemble the template context dictionary.
    """
    print("Querying user TCC database...")
    user_rows = query_tcc_database(TCC_USER_DB, "user")
    print(f"  Found {len(user_rows)} entries")

    print("Querying system TCC database...")
    system_rows = query_tcc_database(TCC_SYSTEM_DB, "system")
    print(f"  Found {len(system_rows)} entries")

    all_rows = user_rows + system_rows

    print("Discovering installed applications...")
    installed_apps = discover_installed_apps()
    print(f"  Found {len(installed_apps)} apps")

    # ── Classify each TCC row ──────────────────────────────────────────

    # We only care about services that map to a report category.
    relevant_services = set()
    for cat in CATEGORIES:
        relevant_services.update(cat["services"])

    # Allowed grants, grouped by category ID
    grants_by_category: dict[str, list[PermissionGrant]] = {cat["id"]: [] for cat in CATEGORIES}
    # Ghost entries (allowed grants for uninstalled apps)
    ghosts: list[PermissionGrant] = []
    # Track all permissions per client for concentration analysis
    perms_per_client: dict[str, list[str]] = {}

    for row in all_rows:
        service = row["service"]
        if service not in relevant_services:
            continue
        if row["auth_value"] != AUTH_ALLOWED:
            continue

        client = row["client"]
        client_type = row["client_type"]
        cat_id = _SERVICE_TO_CATEGORY[service]

        # Determine installation status
        if client_type == 0:
            is_installed = client in installed_apps
        else:
            is_installed = os.path.exists(client)

        # Skip Apple system daemons (bundle IDs starting with com.apple. that
        # aren't actual user-facing apps in our installed_apps dict)
        if client_type == 0 and client.startswith("com.apple.") and client not in installed_apps:
            # Allow known Apple apps through (Terminal, Shortcuts, Safari)
            if client not in ASSESSMENTS:
                continue

        # Skip system framework binaries (paths under /System/ or /Library/)
        if client_type == 1 and (client.startswith("/System/") or client.startswith("/Library/")):
            continue

        # Skip known helper bundles whose parent app IS installed —
        # the helper's permissions are effectively the parent's.
        if client in KNOWN_HELPERS:
            parent = KNOWN_HELPERS[client]
            if parent in installed_apps:
                continue

        name = friendly_name(client, client_type, installed_apps)
        assessment, label, reason = get_assessment(client, client_type, service)

        grant = PermissionGrant(
            service=service,
            client=client,
            client_type=client_type,
            auth_value=row["auth_value"],
            source=row["source"],
            target=row.get("target", ""),
            app_name=name,
            is_installed=is_installed,
            assessment=assessment,
            assessment_label=label,
            assessment_reason=reason,
        )

        # Extra columns
        if service in SERVICE_FRIENDLY:
            grant.extra["subtype"] = SERVICE_FRIENDLY[service]
        if service == "kTCCServiceAppleEvents" and row.get("target"):
            target_name = friendly_name(row["target"], 0, installed_apps)
            grant.extra["subtype"] = target_name

        if not is_installed:
            ghosts.append(grant)
        else:
            grants_by_category[cat_id].append(grant)
            # Track for concentration analysis
            perms_per_client.setdefault(client, []).append(service)

    # ── Deduplicate path-based entries (multiple uv versions) ─────────
    for cat_id, grants in grants_by_category.items():
        seen_names: dict[str, PermissionGrant] = {}
        deduped = []
        for g in grants:
            if g.client_type == 1:
                key = (g.app_name, g.service)
                if key in seen_names:
                    continue
                seen_names[key] = g
            deduped.append(g)
        grants_by_category[cat_id] = deduped

    # ── Merge per-app Automation rows into single entries ─────────────
    if "automation" in grants_by_category:
        auto_merged: dict[str, PermissionGrant] = {}
        for g in grants_by_category["automation"]:
            if g.client in auto_merged:
                existing = auto_merged[g.client]
                existing.extra["subtype"] = existing.extra.get("subtype", "?") + ", " + g.extra.get("subtype", "?")
            else:
                auto_merged[g.client] = g
        grants_by_category["automation"] = list(auto_merged.values())

    # ── Merge per-app Personal Data rows ──────────────────────────────
    if "personal_data" in grants_by_category:
        pd_merged: dict[str, PermissionGrant] = {}
        for g in grants_by_category["personal_data"]:
            if g.client in pd_merged:
                existing = pd_merged[g.client]
                existing.extra["subtype"] += ", " + g.extra.get("subtype", "?")
                # Use the worst assessment
                if g.assessment == "concern" or (g.assessment == "moderate" and existing.assessment == "ok"):
                    existing.assessment = g.assessment
                    existing.assessment_label = g.assessment_label
                    existing.assessment_reason = g.assessment_reason
            else:
                pd_merged[g.client] = g
        grants_by_category["personal_data"] = list(pd_merged.values())

    # ── Build category data for template ──────────────────────────────
    categories_data = []
    for cat in CATEGORIES:
        apps = grants_by_category[cat["id"]]
        # Sort: concerns first, then moderate, then ok
        order = {"concern": 0, "moderate": 1, "ok": 2}
        apps.sort(key=lambda g: (order.get(g.assessment, 1), g.app_name.lower()))
        categories_data.append({
            **cat,
            "count": len(apps),
            "apps": [
                {
                    "name": g.app_name,
                    "bundle_id": g.client,
                    "assessment": g.assessment,
                    "assessment_label": g.assessment_label,
                    "assessment_reason": g.assessment_reason,
                    "notes": g.notes,
                    "extra": g.extra,
                }
                for g in apps
            ],
        })

    # ── Concentration analysis ────────────────────────────────────────
    #
    # Find apps holding 3+ permissions across the dangerous categories.
    # We label each permission with its risk level for the chip display.

    SERVICE_RISK = {}
    for cat in CATEGORIES:
        for svc in cat["services"]:
            SERVICE_RISK[svc] = cat["risk_level"]

    SERVICE_NAME = {}
    for cat in CATEGORIES:
        for svc in cat["services"]:
            SERVICE_NAME[svc] = cat["name"]

    concentration = []
    for client, services in perms_per_client.items():
        unique = list(dict.fromkeys(services))  # dedupe preserving order
        if len(unique) < 3:
            continue
        ct = 1 if client.startswith("/") else 0
        name = friendly_name(client, ct, installed_apps)
        assessment, label, reason = get_assessment(client, ct, unique[0])
        # For concentration, use the app-level default assessment
        if ct == 0 and client in ASSESSMENTS and "_default" in ASSESSMENTS[client]:
            a, r = ASSESSMENTS[client]["_default"]
            label = ASSESSMENT_LABELS[a]
            reason = r
            assessment = a
        elif ct == 1:
            key = _match_path_key(client)
            if key and "_default" in PATH_ASSESSMENTS.get(key, {}):
                a, r = PATH_ASSESSMENTS[key]["_default"]
                label = ASSESSMENT_LABELS[a]
                reason = r
                assessment = a
        if client in INVASIVE_APPS:
            assessment = "concern"
            label = "Invasive"
            reason = INVASIVE_APPS[client]["concern_reason"]

        perms = [
            {"name": SERVICE_NAME.get(s, s), "risk": SERVICE_RISK.get(s, "medium")}
            for s in unique
        ]
        concentration.append({
            "name": name,
            "assessment": assessment,
            "assessment_label": label,
            "assessment_reason": reason,
            "perms": perms,
        })
    concentration.sort(key=lambda c: (-len(c["perms"]), c["name"]))

    # ── Ghost analysis ────────────────────────────────────────────────
    #
    # Group ghost entries by app, merge permissions, determine risk.

    ghost_merged: dict[str, dict] = {}
    for g in ghosts:
        # For path-based entries, group by friendly name to avoid
        # duplicate entries for e.g. multiple uv/uvx versions.
        key = g.app_name if g.client_type == 1 else g.client
        if key not in ghost_merged:
            ghost_merged[key] = {
                "name": g.app_name,
                "bundle_id": g.client,
                "permissions": [],
            }
        svc_name = SERVICE_NAME.get(g.service, g.service)
        risk = SERVICE_RISK.get(g.service, "medium")
        entry = ghost_merged[key]
        if svc_name not in [p["name"] for p in entry["permissions"]]:
            entry["permissions"].append({"name": svc_name, "risk": risk})

    ghost_list = sorted(ghost_merged.values(), key=lambda g: -len(g["permissions"]))
    for g in ghost_list:
        has_critical = any(p["risk"] == "critical" for p in g["permissions"])
        g["risk_label"] = "Critical" if has_critical else "High"
        g["risk_class"] = "concern" if has_critical else "moderate"

    # ── Alert banners for invasive apps ───────────────────────────────
    alerts = []
    for bundle_id, info in INVASIVE_APPS.items():
        # Only show banner if the app actually has allowed permissions
        has_perms = any(
            g.client == bundle_id and g.auth_value == AUTH_ALLOWED
            for cat_grants in grants_by_category.values()
            for g in cat_grants
        )
        if has_perms:
            perm_names = []
            for cat_grants in grants_by_category.values():
                for g in cat_grants:
                    if g.client == bundle_id:
                        sname = SERVICE_NAME.get(g.service, g.service)
                        if sname not in perm_names:
                            perm_names.append(sname)
            alerts.append({
                **info,
                "bundle_id": bundle_id,
                "active_permissions": perm_names,
            })

    # ── Summary stats ─────────────────────────────────────────────────
    critical_count = sum(
        len(grants_by_category[cat["id"]])
        for cat in CATEGORIES
        if cat["risk_level"] == "critical"
    )
    sensor_count = sum(
        len(grants_by_category[cat["id"]])
        for cat in CATEGORIES
        if cat["risk_level"] == "high"
    )
    all_apps = set()
    for grants in grants_by_category.values():
        for g in grants:
            all_apps.add(g.client)

    stats = {
        "critical_grants": critical_count,
        "sensor_grants": sensor_count,
        "installed_apps": len(all_apps),
        "ghost_entries": len(ghost_list),
    }

    # ── System info ───────────────────────────────────────────────────
    sys_info = get_system_info()

    return {
        "sys_info": sys_info,
        "stats": stats,
        "alerts": alerts,
        "concentration": concentration,
        "categories": categories_data,
        "ghosts": ghost_list,
        "system_db_readable": len(system_rows) > 0,
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Report Generation
# ═══════════════════════════════════════════════════════════════════════════════

def generate_report(output_path: Path) -> None:
    """Build all audit data and render the HTML report."""
    print("=" * 60)
    print("  macOS Privacy Permission Audit")
    print("=" * 60)

    context = build_report_data()

    print("\nRendering report...")
    template_dir = Path(__file__).parent
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("template.html")
    html = template.render(**context)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    print(f"\nReport written to: {output_path}")
    print("Done!")


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Generate a macOS privacy permission audit report.")
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path.home() / "Downloads" / "privacy_audit.html",
        help="Output path for the HTML report (default: ~/Downloads/privacy_audit.html)",
    )
    args = parser.parse_args()
    generate_report(args.output)


if __name__ == "__main__":
    main()
