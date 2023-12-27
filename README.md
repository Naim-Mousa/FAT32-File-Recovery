# FAT32 File Recovery Tool

## Overview

This tool is designed for recovering files from a FAT32 file system. It supports various operations including printing file system information, listing the root directory, and recovering deleted files, with optional SHA1 hash verification for file integrity.

## Features

- **Print File System Information:** Display key details about the FAT32 file system.
- **List Root Directory:** Enumerate files and directories in the root directory.
- **Recover Files:** Capabilities to recover both contiguous and non-contiguous files.
- **SHA1 Verification:** Option to recover files with SHA1 hash verification for ensuring file integrity.

## Usage
`./nyufile disk <options>`
- `-i`: Print the file system information.
- `-l`: List the root directory.
- `-r filename [-s sha1]`: Recover a contiguous file.
- `-R filename -s sha1`: Recover a possibly non-contiguous file.

**Examples**
- `./nyufile disk.img -i`
- `./nyufile disk.img -l`
- `./nyufile disk.img -r example.txt`
- `./nyufile disk.img -R example.txt -s <sha1-hash>`

## Installation
1. **Clone the Repository**: `git clone https://github.com/Naim-Mousa/FAT32-File-Recovery-Tool.git`
2. **Navigate to the Directory**: `cd FAT32-File-Recovery-Tool`
3. **Compile the Program**: `Make`

## Important Specifications
- You **must** unmount the disk before running the program.
- The program assumes that the deleted file is in the root directory.
- Ensure that **no other** files or directories are created or modified since the deletion of the target file. However, multiple files may be deleted.
- The program can only recover **contiguously allocated files**.
