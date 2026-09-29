# OmniDeleter

**Windows advanced permanent file deletion utility**

![image](https://i.postimg.cc/CMtq07zJ/2026-09-29-223130.png)


Version: `v2026.09.29`

OmniDeleter is a Windows desktop file-processing and permanent-deletion utility. In addition to handling files and directories that ordinary Windows operations may have difficulty deleting, it provides single-file rename support and non-destructive path rescue for unusually deep or long directory paths.

- The rename dialog edits only the filename stem; the existing file extension is preserved and restored automatically.

> [!CAUTION]
> **This is a destructive tool with irreversible operations.**
>
> OmniDeleter includes an irreversible Permanent Delete capability, while also providing non-destructive file rename and directory path rescue. After a permanent deletion succeeds, users must not assume that the data can be recovered through the Recycle Bin, ordinary recovery tools, or any other method.
>
> **Before any deletion, personally verify the target, back up important data, and make sure that no other drive, directory, system location, or active work has been selected by mistake.**

---

## 1. Most Important User Warnings

OmniDeleter is not a normal "Move to Recycle Bin" tool, and it is not a file-recovery tool.

Users are responsible for the risk of data loss arising from operation, configuration, path selection, permissions, third-party software, Windows itself, or any other cause.

In particular:

- **Permanent deletion is irreversible.**
- Do not process unknown, unverified, or important directories unless you have independently confirmed that they may be removed.
- Do not assume that a target is safe or unimportant merely because the program reports that it can process it.
- Do not delete system, boot, recovery, service, application-installation, user-profile, or other files whose purpose you do not understand.
- When processing files held open by another process, forced handling may terminate the related process. Make sure the process can safely be closed and that its work has been saved.
- When processing Explorer / Shell-related targets, the Windows desktop may temporarily refresh or restart.
- Behavior involving third-party applications, drivers, synchronization tools, cloud file systems, or special file systems may depend on Windows and third-party implementations.
- **A successful deletion does not mean that all underlying data has been physically erased or that every possible recovery method has become impossible.** OmniDeleter is a file-system-level permanent deletion utility, not a secure data-erasure, disk degaussing, or SSD secure-erase tool.

---

## 2.0 Folder Picker

The Add Folder operation uses the modern Windows `IFileOpenDialog` folder-selection mode. Drag-and-drop addition uses the same downstream path-processing architecture, so deep / long directory selection no longer depends on the legacy `SHBrowseForFolderW` tree-style folder browser. Windows documentation recommends `IFileDialog` with `FOS_PICKFOLDERS` for folder selection on Windows Vista and later.

## 2. Main Features

### File Rename

Only one file may be renamed at a time. The dialog accepts a new legal Windows filename while the original extension remains outside the editable field and is preserved automatically. An existing file with the destination name is not overwritten. If the rename fails, the original file remains in place.

The implementation uses a file handle with `SetFileInformationByHandle(FileRenameInfo)` and passes a fully qualified `\\?\` destination path with `RootDirectory = NULL`, so the destination does not depend on the process current working directory. Source-object identity handling is retained for conservative failure paths.

In the main interface, the Rename File action is enabled only when exactly one file is selected. It is disabled for no selection, multiple selection, or a selected directory.

### Directory Path Rescue

Only one directory may be rescued at a time. This feature is intended for situations in which the selected directory is located below an unusually deep or long path and ordinary Explorer / Shell operations may have difficulty handling it.

The tool creates a unique empty `OmniDeleter_x` container at the root of the volume containing the selected directory, then moves the selected original directory itself to:

```text
<VolumeRoot>\OmniDeleter_x\A
```

`A` is the original directory itself. Its files, subdirectories, names, and internal hierarchy are not rewritten by the rescue operation. Only `x` changes to avoid a collision at the first level; `A` is always fixed.

After a successful Path Rescue, the original deep parent directory is not deleted or reorganized. Users may later clean up the old parent path in Explorer or add it to OmniDeleter for Permanent Delete if appropriate.

Path Rescue does not cross volumes, does not use Copy-then-Delete, does not intentionally delete the source when the move fails, and does not automatically terminate processes holding the source.

In the main interface, the Directory Rescue action is enabled only when exactly one directory is selected. It is disabled for no selection, multiple selection, or a selected file.

After a successful rescue, the rescued directory is removed from the current OmniDeleter target list. The rescue destination is shown in the success message so the user can locate the rescued object without leaving it in the deletion queue.

### Permanent File Delete

Handles ordinary files and some Windows-specific file situations and removes them without sending them to the Windows Recycle Bin.

### Permanent Directory Delete

Supports recursive directory processing. Files and child directories are processed according to their actual state.

### Long Paths

Provides handling for Windows long-path scenarios.

### Unicode Names

Supports ordinary Unicode paths and filenames. When a path contains special UTF-16 data that cannot be represented safely, the program uses conservative handling rather than deleting a target whose identity cannot be confirmed.

### Read-Only Items

Provides corresponding handling for read-only targets, including restoration logic when an operation fails after changing file attributes.

### Reparse Point Safety

Windows Reparse Points are handled conservatively:

- Name-surrogate reparse types are not recursively traversed into their targets.
- Only known and policy-allowed provider types are processed according to their handling rules.
- Unknown types that cannot be classified safely are rejected.

OmniDeleter should therefore not be interpreted as a tool that automatically follows every junction, symbolic link, or reparse point and deletes its target.

---

## 3. Forced Handling of Locked Files

This is one of OmniDeleter's primary advanced capabilities.

When a target is in use by another process, the program first attempts to identify related processes and then applies additional security checks before any forced handling is attempted.

Typical flow:

```text
Identify related processes
          ↓
Re-validate process identity
          ↓
User confirms forced handling
          ↓
Terminate confirmed processes that pass safety checks
          ↓
Wait for Windows to release files / images / DLLs and related resources
          ↓
Re-process the original top-level targets confirmed by the user
          ↓
Complete permanent deletion
```

This design avoids the historical failure mode in which the user had to press Permanent Delete a second time after the blocking process had been released.

**Forced handling does not mean unconditional process termination.**

Immediately before termination, the program re-checks factors including:

- PID
- Process Creation Time
- User SID
- Windows Session
- AuthenticationId when available
- Critical Process status
- Protected Process / PPL status
- Windows Service / Service Account characteristics
- Explorer system-image identity

Therefore, even if Windows reuses a PID during a wait, an old approval should not automatically be applied to the new process.

---

## 4. Explorer / Desktop Shell Recovery

When a deletion operation involves Windows Explorer / the Desktop Shell, the program includes a corresponding recovery path.

Design points include:

- Only a process matching the required system Explorer identity is accepted.
- The original user Shell token is saved before termination.
- The original process must be confirmed as exited before the next stage.
- After processing, the Shell is restored under the original user identity.
- The restored identity is checked.
- Required cleanup / recovery is still attempted when an error or panic occurs.

This does not guarantee that the desktop will never be temporarily affected on every Windows version, every third-party Shell extension configuration, every security product, or every system state.

---

## 5. Path Protection

OmniDeleter applies protection to high-risk paths, including:

- Volume roots
- UNC roots
- Protected Windows system paths
- Other high-risk locations used by Windows or applications

Even when a target is selected successfully through the normal UI, path checks are performed again before destructive operations begin.

**Path protection is not an absolute safety guarantee.**

Windows redirection, junctions, reparse points, network paths, third-party file systems, race conditions, and other system components can affect actual behavior. Users must therefore verify the target themselves.

---

## 6. Cancellation and Retries

Deletion processing and selected waiting operations support cancellation.

Short-lived post-force states use bounded settle / retry periods rather than waiting indefinitely.

Such retries apply only to deletion targets originally confirmed by the user. A newly appearing process does not inherit a previous termination authorization automatically.

---

## 7. Startup

`OmniDeleter.exe` is a Windows GUI application.

A normal double-click launch should not create a separate command prompt window.

---

## 8. Permissions and Windows Environment

Some OmniDeleter capabilities are constrained by the Windows security and permission model.

For example:

- Some system files may require elevated permissions.
- Some processes cannot be terminated by an ordinary user.
- Protected Process / PPL, services, system processes, and resources protected by Windows may refuse access or termination.
- Antivirus, EDR, DLP, synchronization tools, or other security products may intercept or delay file operations.
- Different Windows versions, update states, file systems, and system policies may produce different results.

Therefore, **the ability to identify a process does not mean Windows will necessarily permit terminating it, and an attempted delete does not mean Windows will necessarily permit the deletion.**

---

# 9. Complete Disclaimer

## 9.1 General Disclaimer

OmniDeleter is provided **AS IS** and **AS AVAILABLE**. The author, contributors, and distributor make no express or implied warranties regarding suitability, completeness, continued availability, error-free operation, uninterrupted operation, or fitness for a particular purpose.

By downloading, installing, running, or otherwise using OmniDeleter, the user acknowledges that the program can have real and irreversible effects on the file system and on running processes.

## 9.2 Data Loss

**The user assumes all risks of data loss caused by, potentially caused by, or related to the use of OmniDeleter.**

This includes, without limitation:

- Accidental file deletion
- Accidental directory deletion
- Accidental deletion of large numbers of files
- Selecting the wrong drive or path
- Unintended deletion caused by path, redirection, or file-system behavior
- Data loss caused by Windows or third-party software behavior
- Data loss caused by program errors or exceptional conditions
- Irreversible loss caused by failing to create a usable backup before operation

**Create and verify a usable backup before any destructive operation.**

## 9.3 Forced Process Termination

When the user confirms forced handling, OmniDeleter may terminate processes that pass the program's safety checks.

Possible consequences include:

- Loss of unsaved work
- Abnormal process termination
- Loss of temporary data
- Application state changes
- Background service interruption
- Other cascading effects caused by process termination

Users must independently verify that a process can be safely terminated.

OmniDeleter does not guarantee that a third-party process will recover its internal state correctly after forced termination.

## 9.4 Explorer / Shell / System Components

Operations involving Explorer, Shell, DLLs, Windows services, or other system-related components may cause:

- Explorer to exit temporarily
- Desktop refreshes
- Temporary Shell unavailability
- Taskbar or desktop reinitialization
- Effects on third-party Shell extensions
- Other Windows components to reload or change state

Although the program includes recovery mechanisms, **it does not guarantee that all effects can be avoided on every Windows version, with every third-party Shell extension, every security product, or every system state.**

## 9.5 System Files and Important Data

**Do not assume that a file is safe to delete merely because OmniDeleter provides a way to process it.**

Deleting Windows system files, boot files, recovery files, service binaries, drivers, application installation directories, user settings, databases, synchronized folders, or other important data can cause operating-system or application failures.

Users are responsible for deciding whether each target can safely be deleted.

## 9.6 Third-Party Software and External Environment

OmniDeleter does not control:

- The Windows operating system
- NTFS or other file systems
- Explorer
- Antivirus / EDR / DLP products
- Cloud synchronization tools
- Backup software
- Virtualization software
- Third-party Shell extensions
- Third-party processes and services
- Network file systems
- Storage-device firmware or hardware

Behavior caused by or jointly caused by these components cannot be fully controlled or guaranteed by OmniDeleter.

## 9.7 Data Recovery and Secure Erasure

OmniDeleter's Permanent Delete means removal of the target from the Windows file-system namespace.

**It is not a secure data-erasure tool and does not guarantee that original data on physical storage has been overwritten in a forensic or otherwise unrecoverable manner.**

This distinction is especially important for SSDs, NVMe devices, Copy-on-Write systems, snapshots, virtual disks, RAID, cloud synchronization, and other environments with additional data layers.

If a task must satisfy a specific legal, regulatory, corporate-retention, information-security, or media-sanitization requirement, use a dedicated solution that has been appropriately validated for that requirement.

## 9.8 User Responsibility

The user is ultimately responsible for determining:

1. Whether the target path is correct.
2. Whether the target contents may be deleted.
3. Whether necessary backups have been completed.
4. Whether another user, process, or service is using the data.
5. Whether the consequences of forced process termination are understood.
6. Whether the operation complies with applicable law, organizational policy, retention policy, and other requirements.
7. Whether synchronization, backup, services, or related applications should be stopped first.

## 9.9 Limitation of Liability

To the maximum extent permitted by applicable law, the author, contributors, and distributor are not liable for any direct, indirect, incidental, special, consequential, punitive, or other damages arising from the use, inability to use, misuse, reliance on, or inability to rely on OmniDeleter, including without limitation:

- Data loss
- Data corruption
- Business interruption
- Lost profits
- Lost productivity
- System failure
- Process termination
- Operating-system malfunction
- Backup failure
- Third-party software malfunction
- Storage-device damage
- Any other consequential loss

These limitations are subject to applicable law. Where a jurisdiction does not allow exclusion or limitation of certain liabilities, the applicable limitation applies only to the extent legally permitted.

## 9.10 No Professional Advice

OmniDeleter does not provide:

- Legal advice
- Information-security compliance certification
- Digital-forensics guarantees
- Data-recovery guarantees
- Systems-administration guarantees
- Data-erasure compliance guarantees
- Compliance certification for any specific industry or regulatory requirement

Users should obtain appropriate legal, security, systems-administration, or data-governance advice for specialized requirements.

## 9.11 Final Pre-Operation Check

Before any operation with irreversible consequences, confirm again:

- The complete path of every item in the target list.
- The selected drive, volume, directory, and file are correct.
- Important content has a usable backup.
- No application, service, synchronization tool, or other user is actively using the target.
- Directory Rescue is a move, not a backup; after a successful rescue, no second copy is automatically created.
- Permanent Delete does not send data to the Recycle Bin and carries an irreversible-loss risk.

If any of these points cannot be answered clearly, do not perform Permanent Delete.

# 10. Safe-Use Recommendations

Before performing Permanent Delete, consider this sequence:

```text
1. Verify the complete path
2. Verify the filename / directory name
3. Verify that the correct drive is selected
4. Verify that important data has been backed up
5. Close applications using the target
6. Consider whether another user may be affected
7. Perform Permanent Delete only after the above checks
```

For especially important data, validate the workflow on a **copy** first.

---

# 11. Release Description

This release contains the following established functionality and safety handling:

- Permanent deletion: preserves the one-confirmation forced-handling flow in which the original top-level targets are re-processed after confirmed blocker termination.
- File Rename: one file at a time; the editable field contains only the filename stem; the original extension is preserved automatically; legal spaces are accepted; existing destination files are not overwritten; the destination is specified as a fully qualified absolute path.
- Directory Rescue: one directory at a time; creates a unique empty `OmniDeleter_x` container at the same volume root and moves the original directory itself to `OmniDeleter_x\A`; removes the rescued item from the current target list after success; does not intentionally delete the original deep parent path.
- Add Folder: uses the modern Windows folder picker and supports deep / long-path selection scenarios.
- Existing Locker / Explorer recovery, path protection, Reparse Point handling, Unicode handling, long-path handling, read-only handling, cancellation, and bounded retries remain part of the established architecture.
- The main window remains the 695x530 Classic Windows layout with the established interaction model. Newly added feature buttons use the same standard Windows button style.

OmniDeleter remains a high-risk file-system tool. A program message indicating that an item is "processable", "successful", or "completed" does not replace the user's responsibility to confirm the target path, the importance of the data, and the backup state.

# 12. Version and Licensing

Project version: `v2026.09.29`

Author / distributor: `@thunderx2012`

Refer to the LICENSE file supplied by the project repository for the governing license terms.

This README's safety statements and disclaimer do not replace the governing license, applicable law, organizational policy, or any written contract.

---

## Final Warning

> **When you press Permanent Delete, treat the data as potentially gone forever.**
>
> Before using OmniDeleter, make sure you know **what you are deleting, why you are deleting it, whether it is backed up, and whether you can accept the consequences**.
>
> **When in doubt, do not delete.**
