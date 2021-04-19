# chunkdisk

Mount a disk image split over files (*chunks*) in multiple directories (*parts*).

## Getting Started

I'm not responsible for the data stored using chunkdisk!

1. Install [WinSpd](https://github.com/billziss-gh/winspd/releases/tag/v1.0B1).
2. Copy chunkdisk-x64.exe to C:\Program Files (x86)\WinSpd\bin\.
3. Merge install.reg.
4. Create a `.chunkdisk` file. For example:

    ```plaintext
    107374182400
    104857600
    512 C:\part1
    512 C:\part2
    ```

5. Create directories specified in the file, for example: C:\part1, C:\part2.
6. Right-click the file in File Explorer and choose "Mount".
7. Run `diskmgmt.msc` to open Disk Management, [initialize the disk](https://docs.microsoft.com/en-us/windows-server/storage/disk-management/initialize-new-disks) and [create a partition](https://support.microsoft.com/en-us/windows/create-and-format-a-hard-disk-partition-bbb8e185-1bda-ecd1-3465-c9728f7d7d2e).
8. To dismount, right-click the drive in File Explorer and choose "Eject".

## WARNINGS

* MAKE A BACKUP of `.chunkdisk` file. Chunkdisk reads it only once when it's mounted. It can be read, modified and even deleted by others while the disk is mounted.
* DO NOT add, remove and move around chunk files when the disk is mounted. Doing so confuses chunkdisk and causes I/O errors.
* DO NOT directly modify chunk files. They are NOT write-protected even when being used.

## `.chunkdisk` File Specs

```plaintext
{disk size in bytes}
{chunk file size in bytes}
{max. number of chunks} {absolute path to a directory}
{max. number of chunks} {absolute path to a directory}
...
```

* UTF-8 encoding
* Disk size and chunk size must be a multiple of 4096.
* The sum of max. number of chunks must be at least (Disk size) / (Chunk size) + surplus (0 ~ 1).

## Issues

* Random I/O performance is not great with SSDs.

## Notes and Tips

* A chunk file is created in directories from top to bottom in `.chunkdisk` file when it is written by the virtual disk. It is zero-initialized so it may take time if the chunk size is large. You may specify different drives for different parts. Make sure disk spaces are sufficient for new chunks.

* If you want to place specific chunk to specific part, you may create an empty chunk file in that part in prior while the disk is not mounted. A chunk (a region of the virtual disk) has three states. The corresponding file (`chunk###`) may not exist, be empty (zero bytes) and be of full size. Data of a region is zero if its backing chunk file does not exist or is empty.

* You may move chunk files to different parts to redistribute the space usage while the disk is not mounted.

* When a file in the virtual disk gets deleted the corresponding chunk file may become empty if it is larger than the chunk size. This is done via SCSI UNMAP command (a.k.a. TRIM) requested by Windows.

* You can identify the file in disk for specific chunk or identify the chunk used by specific file. Use `fsutil volume querycluster` for the former, `fsutil file queryextents` for the latter. Use `diskpart` to know the partition offset. For NTFS volumes the cluster size is typically 4096 and LCN 0 corresponds to offset from 0 (inclusive) to 4096 (exclusive) of the partition.
