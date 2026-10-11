#!/usr/bin/env python3
"""Publish the final video publicly: Google Drive (rclone) or YouTube (Data API v3).

  python tools/publish.py drive   [--remote gdrive] [--folder "Warden demo"]
  python tools/publish.py youtube --client-secret ~/.config/warden-video/client_secret.json [--privacy unlisted]

Drive needs a one-time `rclone config create gdrive drive scope=drive.file` (opens a browser for consent).
YouTube needs an OAuth "Desktop app" client from Google Cloud with the YouTube Data API v3 enabled;
the first run opens a browser for consent and caches the token next to the client secret.
Both print the public link, then verify it opens without logging in.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FINAL = ROOT / "build" / "final" / "warden_demo.mp4"
SRT = ROOT / "build" / "captions" / "final.srt"


def description() -> str:
    tl = json.loads((ROOT / "plan" / "timeline.json").read_text())
    chapters = "\n".join(f"{int(s['start'] // 60)}:{int(s['start'] % 60):02d} {s['name']}" for s in tl["sections"])
    attrib = (ROOT / "build" / "clips" / "ATTRIBUTION.md")
    credits = attrib.read_text().strip() if attrib.exists() else ""
    return (
        "Warden is an open-source firewall for AI agents. It reads web pages, files, email and tool results "
        "before your assistant does, and stops the hidden instructions inside them.\n\n"
        "Install: bunx @shivdev/agent-warden --api-only\n"
        "GitHub: https://github.com/ShivShankarDash/warden\nnpm: https://www.npmjs.com/package/@shivdev/agent-warden\n\n"
        f"Chapters\n{chapters}\n\n"
        "Every terminal command, verdict and dashboard frame in this video is a real recording of Warden v0.4.0.\n\n"
        + (f"Creative Commons footage\n{credits}\n" if credits else "")
    )


def verify_public(url: str) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read(200_000).decode("utf-8", "ignore")
            # A public Drive/YouTube page carries the file or video title; a private one redirects to sign-in.
            title = body.split("<title>", 1)[-1].split("</title>", 1)[0] if "<title>" in body else ""
            public = bool(title) and "sign in" not in title.lower() and "accounts.google.com" not in r.geturl()
            print(f"verify: HTTP {r.status}, title '{title}' -> {'publicly reachable' if public else 'LOGIN WALL'}")
    except Exception as e:  # noqa: BLE001
        print(f"verify failed: {e}")


def drive(remote: str, folder: str) -> None:
    dest = f"{remote}:{folder}"
    subprocess.run(["rclone", "copy", str(FINAL), dest, "--progress"], check=True)
    if SRT.exists():
        subprocess.run(["rclone", "copy", str(SRT), dest], check=True)
    link = subprocess.run(["rclone", "link", f"{dest}/{FINAL.name}"], capture_output=True, text=True, check=True).stdout.strip()
    if "open?id=" in link:  # the /file/d/<id>/view form opens the player directly
        link = f"https://drive.google.com/file/d/{link.split('open?id=')[1]}/view"
    print(f"Drive link (anyone with the link can view): {link}")
    (ROOT / "build" / "final" / "PUBLISHED.txt").write_text(f"drive {link}\n")
    verify_public(link)


def youtube(client_secret: str, privacy: str) -> None:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload

    scopes = ["https://www.googleapis.com/auth/youtube.upload", "https://www.googleapis.com/auth/youtube.force-ssl"]
    tok = Path(client_secret).with_name("youtube_token.json")
    creds = Credentials.from_authorized_user_file(str(tok), scopes) if tok.exists() else None
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            creds = InstalledAppFlow.from_client_secrets_file(client_secret, scopes).run_local_server(port=0)
        tok.write_text(creds.to_json())
    yt = build("youtube", "v3", credentials=creds)
    body = {"snippet": {"title": "Warden: a firewall for AI agents (product walkthrough)", "description": description(),
                        "tags": ["prompt injection", "AI security", "MCP", "Kiro", "Claude Code", "agent security"], "categoryId": "28"},
            "status": {"privacyStatus": privacy, "selfDeclaredMadeForKids": False}}
    req = yt.videos().insert(part="snippet,status", body=body, media_body=MediaFileUpload(str(FINAL), chunksize=8 * 1024 * 1024, resumable=True))
    resp = None
    while resp is None:
        status, resp = req.next_chunk()
        if status:
            print(f"  uploaded {int(status.progress() * 100)}%")
    vid = resp["id"]
    if SRT.exists():
        yt.captions().insert(part="snippet", body={"snippet": {"videoId": vid, "language": "en", "name": "English"}},
                             media_body=MediaFileUpload(str(SRT))).execute()
    link = f"https://youtu.be/{vid}"
    print(f"YouTube ({privacy}): {link}")
    (ROOT / "build" / "final" / "PUBLISHED.txt").write_text(f"youtube {link}\n")
    verify_public(link)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", choices=["drive", "youtube", "description"])
    ap.add_argument("--remote", default="gdrive")
    ap.add_argument("--folder", default="Warden demo")
    ap.add_argument("--client-secret", default=str(Path.home() / ".config" / "warden-video" / "client_secret.json"))
    ap.add_argument("--privacy", default="unlisted", choices=["unlisted", "public"])
    a = ap.parse_args()
    if a.target == "drive":
        drive(a.remote, a.folder)
    elif a.target == "youtube":
        youtube(a.client_secret, a.privacy)
    else:
        print(description())


if __name__ == "__main__":
    main()
