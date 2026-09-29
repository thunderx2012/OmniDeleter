# OmniDeleter v2026.09.29

## Formal Release

This is the formal Windows x64 GUI release. Its behavior is based on the currently verified production baseline.

### File Rename

- Processes exactly one selected file at a time.
- The rename field edits only the filename stem; the original extension is preserved automatically.
- Legal spaces in filenames are accepted.
- Windows-forbidden characters, control characters, and existing filename restrictions remain rejected.
- Existing files with the destination name are not overwritten.
- The Win32 rename operation uses a fully qualified absolute destination path and does not depend on the process current working directory.

### Directory Rescue

- Processes exactly one selected directory at a time.
- Creates a unique empty `OmniDeleter_x` container at the root of the same volume.
- Moves the original directory itself to `OmniDeleter_x\A`.
- Removes the original target from the current target list after successful rescue; the rescued destination is not placed back into the deletion queue.
- Does not use Copy-then-Delete, does not cross volumes, and does not automatically terminate processes holding the source.
- On failure, the source is not intentionally deleted; cleanup is limited to the newly created and identity-verified empty rescue container.

### Long Paths and Folder Selection

- Add Folder uses the Windows `IFileOpenDialog` folder-selection mode.
- Existing Unicode, long-path, read-only, and conservative Reparse Point handling remain in place.

### Deletion and Recovery Core

- Existing permanent-deletion architecture is preserved.
- The one-confirmation forced-handling flow remains in place: after confirmed blocker termination, the original user-confirmed top-level targets are re-processed in the same transaction.
- Existing Locker discovery / recovery, Explorer recovery, Service classification, path protection, self-protection, cancellation, and bounded retries remain unchanged.

### User Interface

- The 695x530 Classic Windows main window is preserved.
- Standard Windows buttons, their existing dimensions, positions, font, and interaction model remain unchanged.
- The empty-list drag hint remains available.
