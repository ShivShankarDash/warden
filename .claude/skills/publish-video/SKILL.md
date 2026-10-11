---
name: publish-video
description: Publishes the finished video to YouTube (unlisted or public, with chapters, attribution and caption track) or Google Drive (anyone-with-the-link), then verifies the link opens without signing in. Use when uploading, sharing or re-publishing the final cut.
---

# Publish

Tool: `video/tools/publish.py`. Publishing is outward-facing, so do it only when the user asked for an upload, and report the exact link.

## Google Drive (rclone)

```bash
brew install rclone                                    # once
rclone config create gdrive drive scope=drive.file     # once: opens a browser, the user clicks Allow
cd video && .venv/bin/python tools/publish.py drive    # copies mp4 + srt to "Warden demo/", prints an anyone-with-link URL
```
`rclone link` sets "anyone with the link: reader" on the file. The `drive.file` scope lets rclone touch only files it created.

## YouTube (Data API v3)

1. In Google Cloud: create a project, enable **YouTube Data API v3**, create an OAuth client of type **Desktop app**, and save its JSON as `~/.config/warden-video/client_secret.json`. Add the uploading account as a test user while the app is in testing mode.
2. Install the client libraries and upload:

```bash
cd video
uv pip install --python .venv/bin/python google-api-python-client google-auth-oauthlib
.venv/bin/python tools/publish.py youtube --privacy unlisted
```
The first run opens a consent page and caches `youtube_token.json`. The upload adds the title, a description with chapters (from `timeline.json`), install commands, Creative Commons attribution (`build/clips/ATTRIBUTION.md`), and the SRT caption track.

Note: videos uploaded through an unverified API project may be locked to private until the project passes Google's audit. If that happens, upload `build/final/warden_demo.mp4` in YouTube Studio by hand and paste `python tools/publish.py description`.

## After publishing

- Open the link in a logged-out or private window (the tool also fetches it). Drive previews can take a few minutes to process a 60 MB file.
- Record the link in `build/final/PUBLISHED.txt` and in the hand-off message.
