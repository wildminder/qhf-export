```markdown
# QHF History Converter

A Python script to parse and convert QIP history files (.qhf format) into more accessible formats: JSON (for structured data) or plain text (for human-readable logs).

## Features

*   Parses binary QHF files used by QIP and QIP Infium.
*   Extracts key metadata: UIN, Nickname, Version.
*   Extracts message details: Timestamp, Sender ("Me" or Contact), Message Text, Direction (Incoming/Outgoing), Message Type Code.
*   Handles the XOR-based message encryption used in standard QHF files.
*   Outputs data in two formats:
    *   **JSON:** Structured data including metadata and a list of message objects.
    *   **TXT:** Plain text file mimicking a standard chat log format.
*   Supports processing a single `.qhf` file or batch processing all `.qhf` files within a specified directory.

## Requirements

*   Python 3.x

## Usage

The script is run from the command line.

```bash
python qhf_converter.py [options] <input_path> [output_path]
```

**Arguments:**

*   `<input_path>`: **Required.** Path to the input `.qhf` file or a directory containing `.qhf` files.
*   `[output_path]`: **Optional.**
    *   If `<input_path>` is a *file*:
        *   If `output_path` is omitted, output is printed to standard output (stdout).
        *   If `output_path` is provided, output is written to the specified file.
    *   If `<input_path>` is a *directory*:
        *   If `output_path` is omitted, output files are saved in a new directory named `qhf_json_output` or `qhf_txt_output` (depending on the format) in the current working directory.
        *   If `output_path` is provided, it must be a directory path where the output files will be saved.

**Options:**

*   `-f FORMAT`, `--format FORMAT`: Specifies the output format.
    *   `json` (default): Output data in JSON format.
    *   `txt`: Output data in plain text format.
*   `-v`, `--verbose`: Enable verbose logging (shows DEBUG level messages).

**Examples:**

1.  **Convert a single file to JSON and print to screen:**
    ```bash
    python qhf_converter.py /path/to/my_history.qhf
    ```

2.  **Convert a single file to TXT and print to screen:**
    ```bash
    python qhf_converter.py -f txt /path/to/my_history.qhf
    ```

3.  **Convert a single file to JSON and save to a specific file:**
    ```bash
    python qhf_converter.py /path/to/my_history.qhf /path/to/output/history_data.json
    ```

4.  **Convert a single file to TXT and save to a specific file:**
    ```bash
    python qhf_converter.py -f txt /path/to/my_history.qhf /path/to/output/history_log.txt
    ```

5.  **Convert all `.qhf` files in a directory to JSON (output to `qhf_json_output` directory):**
    ```bash
    python qhf_converter.py /path/to/qhf_files/
    ```

6.  **Convert all `.qhf` files in a directory to TXT (output to `qhf_txt_output` directory):**
    ```bash
    python qhf_converter.py -f txt /path/to/qhf_files/
    ```

7.  **Convert all `.qhf` files in a directory to TXT into a specific output directory:**
    ```bash
    python qhf_converter.py -f txt /path/to/qhf_files/ /path/to/my_output_logs/
    ```

8.  **Convert with verbose logging:**
    ```bash
    python qhf_converter.py -v /path/to/my_history.qhf output.json
    ```

## QHF File Format Overview

The `.qhf` file format stores chat history for the QIP instant messenger. The structure consists of a header followed by a series of message blocks.

*(Based on descriptions from [MolinRE/QIParser](https://github.com/MolinRE/QIParser) and [alexey-m.ru](https://alexey-m.ru/articles/qip-infium-prodolzhenie-istorii))*

1.  **File Header:**
    *   Starts with the magic bytes `QHF`.
    *   Contains metadata such as format version, file size (potentially inaccurate), message counts (potentially inaccurate), and importantly:
        *   **UIN:** The User Identification Number of the contact.
        *   **Nickname:** The nickname of the contact.
    *   Lengths for UIN and Nickname strings are stored before the strings themselves.
    *   Numeric values are stored in Big Endian format.
    *   Strings (UIN, Nickname) are typically stored in UTF-8 encoding.

2.  **Messages:**
    *   Follow directly after the header, stored sequentially.
    *   Each message block has its own structure, containing fields that define the message properties. Key fields identified and used by this script include:
        *   **Timestamp:** Unix timestamp (seconds since epoch) indicating when the message was sent/received (Offset `0x12`, 4 bytes).
        *   **Direction Flag:** A byte indicating if the message is outgoing (sent by "Me") or incoming (received from the contact) (Offset `0x1A`, 1 byte).
        *   **Message Type Code:** A byte indicating the type of message or event (e.g., 1 for online message, 5 for auth request, 13 for offline message, etc.) (Offset `0x1B`, 1 byte). See `MESSAGE_TYPE_MAP` in the script for known values.
        *   **Message Length:** The length of the encrypted message text in bytes (Last 4 bytes of message header block).
        *   **Message Text:** The actual content of the message.

3.  **Encryption:**
    *   In standard QHF files, the message text is encrypted using a simple byte-wise XOR operation combined with the byte's position within the message. The formula is equivalent to: `decrypted_byte = (encrypted_byte + position) & 0xFF ^ 0xFF` (where `position` starts at 1).
    *   After decryption, the resulting bytes are decoded using UTF-8 encoding.
    *   *Note:* Some sources indicate that QHF files from QIP PDA versions might store message text unencrypted. This script currently assumes encryption is always present.

## Acknowledgements

*   The original format description was taken from [github.com/MolinRE/QIParser](https://github.com/MolinRE/QIParser). Many thanks to the author
```