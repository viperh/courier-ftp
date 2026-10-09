# FileZilla feature reference

Features of the FileZilla client (3.x, free edition) that courier-ftp aims to cover.

## 1. Protocols and connectivity

- FTP, FTP over TLS (explicit and implicit), SFTP over SSH
- Encryption modes: plain only, explicit TLS if available, require explicit TLS, require implicit TLS
- IPv6
- Proxies: HTTP/1.1 CONNECT, SOCKS4/5, and FTP proxies (USER@HOST, SITE, OPEN, custom scripts)
- FTP active and passive mode, with fallback to active, an external IP setting, a limited local port range and an IP lookup service
- Keep-alive commands so idle connections don't drop
- Timeouts and automatic reconnect or retry, with a configurable retry count and delay
- Kerberos/GSS authentication for FTP
- SFTP keys: key files (PuTTY .ppk and OpenSSH), Pageant or SSH agent, and a cached host key fingerprint that you confirm on first connect
- TLS certificate check dialog with a "trust this certificate" store
- Character set per server: auto-detect, forced UTF-8 or a custom encoding
- Server time zone offset per site
- Listing parser that handles many server formats (MLSD, LIST for Unix, Windows/IIS, VMS, MVS and others)

## 2. Connecting and managing sites

- **Quickconnect bar:** host, user, password and port, plus a history dropdown
- **Site Manager**
  - Sites organized in a folder tree; copy, rename, duplicate and drag sites
  - General tab: protocol, host, port, encryption and logon type (anonymous, normal, ask for password, interactive, key file, account), plus a background colour per site
  - Advanced tab: server type, bypass proxy, default local and remote folders, synchronized browsing on connect, directory comparison, time zone offset
  - Transfer settings tab: passive/active/default and a per-site connection limit
  - Charset tab
- Import and export of sites as XML; import from other clients
- **Bookmarks:** global or per site, optionally with synchronized browsing
- **Tabs:** several connections open at once, each with its own panes
- Password storage options: save, don't save, or protect saved passwords with a master password
- Reconnect to the last server, and a recent servers list
- Command-line start: open `filezilla sftp://user@host/path`, `--site=...` or a local path directly

## 3. Interface layout

- Message log pane showing protocol commands and replies, with colours by message type
- Local pane: folder tree plus file list
- Remote pane: folder tree plus file list
- Queue pane with three tabs: queued files, failed transfers, successful transfers
- Status bar: queue size, speed-limit toggle, transfer type indicator, encryption lock or info icon
- Editable address bars for the local and remote paths
- Layout options: classic, explorer or widescreen arrangement, swapping local and remote, showing or hiding each pane
- File list columns: name, size, type, modified, permissions, owner/group; columns can be sorted and reordered
- Sort options: folders first or mixed, case sensitivity
- Display options for size format (bytes, IEC, SI) and date/time format
- Show or hide hidden files, including forcing hidden files to show on servers that hide them
- Directory listing cache, with an option to refresh or not
- Keyboard shortcuts for most actions; the interface is translated into many languages

## 4. File operations

- Upload and download, either right away or added to the queue
- Drag and drop between panes, to and from the OS file manager, and within the remote side to move files
- Create a folder, or create one and enter it; create a new empty file
- Rename, delete (including recursive delete) and refresh
- Change permissions (chmod) with a checkbox or numeric dialog, applied recursively to files only, folders only or both
- View or edit a file in an external editor: the temporary copy is watched and re-uploaded when it changes. File associations decide which editor opens which file type.
- Copy a file's URL to the clipboard, with or without the password or path
- Enter a raw custom command (SITE and similar); a manual transfer dialog
- Remote search: look up files recursively by conditions (name, size, path, date) and download or delete the results
- Local search as well

## 5. Transfer queue

- Persistent queue saved on exit and restored at startup; import and export
- Process, pause and stop the queue; drag to reorder; set priority (lowest to highest)
- Failed transfers can be reset and re-queued
- Per-transfer progress, speed, ETA and bytes done
- What to do when a file already exists: ask, overwrite, overwrite if newer, overwrite if the size differs, overwrite if newer or a different size, resume, rename, skip. This can be set separately for uploads and downloads and applied to all.
- Resume interrupted transfers, including files over 4 GB
- Actions when the queue finishes: none, show a message, play a sound, run a command, sleep, shut down, disconnect, close the app
- The remote listing refreshes automatically after the queue completes

## 6. Transfer settings

- Maximum simultaneous transfers, with separate limits for downloads and uploads
- Speed limits for download and upload, with a burst tolerance and an on/off toggle in the status bar
- Transfer type: Auto, ASCII or Binary, with a list of extensions treated as ASCII, and dotfiles or files without an extension treated as ASCII
- Preserve timestamps of transferred files
- Preallocate disk space before a download
- Replace characters that aren't valid in local filenames
- Behaviour for empty folders and symlinks

## 7. Comparing and syncing folders

- **Directory comparison:** by size or by modification time, with a threshold. Colour coding: yellow for missing on one side, green for newer, red for a different size. An option hides identical files.
- **Synchronized browsing:** both panes follow each other's folder changes (Ctrl+Y). Turning on comparison also turns on synchronized browsing.
- No true one-way or two-way sync; comparison only.

## 8. Filename filters

- Filter sets, each with separate local and remote rules
- Conditions on name, size, attributes or permissions and path, using contains, equals, regex and similar matches, with case sensitivity, and rules that apply to files, folders or both
- Built-in filters (for example CVS/SVN folders and temp files)
- Filters can be applied to transfers too, so filtered-out files are skipped in recursive operations
- A status indicator shows when a filter is active

## 9. Logging and diagnostics

- Message log with a selectable debug level (0–4)
- Log to a file, with a size limit and rotation
- Show the raw directory listing for debugging
- Network configuration wizard that tests active and passive mode against a probe server

## 10. App-level features

- Settings import and export
- Automatic update check
- Optional splash screen and a "connect on start" option
- Runs on Windows, Linux, BSD and macOS
