# -*- coding: utf-8 -*-
import struct
import datetime
import argparse
import os
import json
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


MESSAGE_TYPE_MAP = {
    1: "Online message",
    2: "Message sending date",
    3: "Message sender",
    5: "Authorization request",
    6: "Friend request",
    13: "Offline message",
    14: "Authorization request accepted",
    80: "QIP/ICQ service message (connection)",
    81: "QIP/ICQ service message (birthday)",
}

def parse_qhf_header(f):
    """Parses the header of a QHF file."""
    header_info = {}
    filename_for_log = os.path.basename(f.name) if hasattr(f, 'name') else 'Unknown File'

    # >: Big-endian
    # 3s: Magic bytes (QHF)
    # B: Version (unsigned char)
    # I: File size (unsigned int)
    # 36s: Reserved/Unknown (skip for now)
    # H: UIN Length (unsigned short)
    header_struct_format = '>3sBI36sH'
    header_size = struct.calcsize(header_struct_format)
    header_buf = f.read(header_size)
    if len(header_buf) < header_size:
        raise ValueError(f"[{filename_for_log}] File too small to contain QHF header.")

    (
        magicbytes,
        version,
        _fsz,
        _reserved,
        uin_len,
    ) = struct.unpack(header_struct_format, header_buf)

    if magicbytes != b'QHF':
        raise ValueError(f"[{filename_for_log}] Invalid magic bytes. Expected b'QHF', got {magicbytes!r}")

    header_info['version'] = version

    uin_struct_format = f'>{uin_len}sH'
    uin_struct_size = struct.calcsize(uin_struct_format)
    uin_buf = f.read(uin_struct_size)
    if len(uin_buf) < uin_struct_size:
        raise ValueError(f"[{filename_for_log}] Could not read UIN and Nick Length.")

    (uin_bytes, nick_len) = struct.unpack(uin_struct_format, uin_buf)
    try:
        try:
            header_info['uin'] = uin_bytes.decode('utf8')
        except UnicodeDecodeError:
            logging.warning(f"[{filename_for_log}] UIN decoding as UTF-8 failed, trying latin1.")
            header_info['uin'] = uin_bytes.decode('latin1', errors='replace')
    except Exception as e:
         raise ValueError(f"[{filename_for_log}] Could not decode UIN: {e}")

    nick_struct_format = f'>{nick_len}s'
    nick_struct_size = struct.calcsize(nick_struct_format)
    nick_buf = f.read(nick_struct_size)
    if len(nick_buf) < nick_struct_size:
         raise ValueError(f"[{filename_for_log}] Could not read Nickname.")

    (nick_bytes,) = struct.unpack(nick_struct_format, nick_buf)
    try:
        try:
            header_info['nickname'] = nick_bytes.decode('utf8')
        except UnicodeDecodeError:
            logging.warning(f"[{filename_for_log}] Nickname decoding as UTF-8 failed, trying latin1.")
            header_info['nickname'] = nick_bytes.decode('latin1', errors='replace')
    except Exception as e:
         raise ValueError(f"[{filename_for_log}] Could not decode Nickname: {e}")

    return header_info

def decrypt_message(msg_bytes):
    """Decrypts the message bytes using the QHF XOR algorithm."""
    return bytes(
        map(
            lambda val_pos: (val_pos[0] + val_pos[1]) & 0xFF ^ 0xFF,
            zip(msg_bytes, range(1, len(msg_bytes) + 1)),
        )
    )

def parse_qhf_messages(f, header_info, filename_for_log):
    """Parses messages from the QHF file stream."""
    messages = []

    username = header_info.get('nickname', 'Unknown Contact')
    # Default to 2 if not found
    version = header_info.get('version', 2)

    # message header size
    if version >= 3:
        msg_header_size = 0x23
    else:
        msg_header_size = 0x21

    msg_counter = 0
    while True:
        msg_header = f.read(msg_header_size)
        if not msg_header:
            break

        if len(msg_header) < msg_header_size:
            logging.warning(f"[{filename_for_log}] Incomplete message header found at end of file (read {len(msg_header)} bytes, expected {msg_header_size}). Stopping.")
            break

        msg_counter += 1
        try:
            msg_timestamp_unix = struct.unpack('>I', msg_header[18:22])[0]
            is_outgoing = bool(msg_header[26])
            message_type_code = msg_header[27]
            msg_size_bytes = msg_header[-4:]
            msg_size = struct.unpack('>I', msg_size_bytes)[0]

            # Read/decrypt message body
            msg_body_encrypted = f.read(msg_size)
            if len(msg_body_encrypted) < msg_size:
                logging.warning(f"[{filename_for_log}] Message {msg_counter}: Incomplete message body (read {len(msg_body_encrypted)} bytes, expected {msg_size}). Skipping message.")
                continue

            msg_body_decrypted = decrypt_message(msg_body_encrypted)

            try:
                message_text = msg_body_decrypted.decode('utf8')
            except UnicodeDecodeError:
                logging.warning(f"[{filename_for_log}] Message {msg_counter}: UTF-8 decoding failed, trying latin1.")
                message_text = msg_body_decrypted.decode('latin1', errors='replace')

            sender = 'Me' if is_outgoing else username
            timestamp_dt = datetime.datetime.fromtimestamp(msg_timestamp_unix, tz=datetime.timezone.utc)
            timestamp_iso = timestamp_dt.isoformat()
            message_type_description = MESSAGE_TYPE_MAP.get(message_type_code, "Unknown")

            messages.append({
                "sender": sender,
                "timestamp_unix": msg_timestamp_unix,
                "timestamp_iso": timestamp_iso,
                "is_outgoing": is_outgoing,
                "message_type_code": message_type_code,
                "message_type_description": message_type_description,
                "text": message_text
            })

        except struct.error as e:
            logging.error(f"[{filename_for_log}] Message {msg_counter}: Error unpacking message header/data: {e}. Skipping rest of file.")
            break
        except Exception as e:
            logging.error(f"[{filename_for_log}] Message {msg_counter}: Unexpected error processing message: {e}. Skipping message.")
            continue

    return messages

def parse_qhf_file(infile_path):
    """Reads a QHF file and returns header info and a list of message dictionaries."""
    logging.info(f"Processing file: {infile_path}")
    filename_for_log = os.path.basename(infile_path)
    try:
        with open(infile_path, 'rb') as f:
            header_info = parse_qhf_header(f)
            messages = parse_qhf_messages(f, header_info, filename_for_log)

        logging.info(f"Successfully parsed {len(messages)} messages from {infile_path}")
        return header_info, messages

    except FileNotFoundError:
        logging.error(f"Input file not found: {infile_path}")
        return None, None
    except ValueError as e:
        logging.error(f"Error parsing QHF file {infile_path}: {e}")
        return None, None
    except Exception as e:
        logging.error(f"An unexpected error occurred while processing {infile_path}: {e}")
        return None, None

def format_log_entry(name, timestamp_dt, message):
    """Formats a single message entry for plain text output."""
    timestamp_str = timestamp_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    return '\n'.join([
        f"{name} [{timestamp_str}]",
        message,
    ])

def main():
    parser = argparse.ArgumentParser(
        prog='qhf_converter.py',
        description='Reads QHF (QIP History File) format and exports data to JSON or TXT.',
        epilog='Can process a single file or all *.qhf files in a directory.'
    )
    parser.add_argument(
        'input_path',
        type=str,
        help='Path to the input QHF file or a directory containing QHF files.'
    )
    parser.add_argument(
        'output_path',
        type=str,
        nargs='?', # Make output optional
        help='Path to the output file or directory. If omitted and input is a file, outputs to stdout. If omitted and input is a directory, outputs to a directory named "qhf_output".'
    )
    parser.add_argument(
        '-f', '--format',
        type=str.lower,
        choices=['json', 'txt'],
        default='json',
        help='Output format: "json" (default) or "txt".'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging (DEBUG level).'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    input_path = args.input_path
    output_path = args.output_path
    output_format = args.format

    # Determine if input is file or directory
    is_input_dir = os.path.isdir(input_path)
    is_input_file = os.path.isfile(input_path)

    if not is_input_dir and not is_input_file:
        logging.error(f"Input path '{input_path}' is not a valid file or directory.")
        sys.exit(1)

    # Single File Processing
    if is_input_file:
        if not input_path.lower().endswith('.qhf'):
             logging.warning(f"Input file '{input_path}' does not have a .qhf extension.")

        header_info, messages = parse_qhf_file(input_path)

        if header_info is not None and messages is not None:
            output_content = ""
            if output_format == 'json':
                json_data = {
                    "uin": header_info.get('uin', 'N/A'),
                    "nickname": header_info.get('nickname', 'N/A'),
                    "messages": messages
                }
                try:
                    output_content = json.dumps(json_data, indent=4, ensure_ascii=False)
                except TypeError as e:
                    logging.error(f"Error serializing data to JSON for {input_path}: {e}")
                    sys.exit(1)

            elif output_format == 'txt':
                formatted_entries = []
                contact_name = header_info.get('nickname', 'Unknown Contact')
                for msg in messages:
                    sender_name = "Me" if msg['is_outgoing'] else contact_name
                    timestamp_dt = datetime.datetime.fromisoformat(msg['timestamp_iso'])
                    formatted_entries.append(
                        format_log_entry(sender_name, timestamp_dt, msg['text'])
                    )
                output_content = '\n\n'.join(formatted_entries)

            # Write output
            if output_path:
                output_dir_path = os.path.dirname(output_path)
                if output_dir_path and not os.path.exists(output_dir_path):
                     try:
                         os.makedirs(output_dir_path)
                         logging.info(f"Created output directory: {output_dir_path}")
                     except OSError as e:
                         logging.error(f"Could not create output directory {output_dir_path}: {e}")
                         sys.exit(1)
                try:
                    with open(output_path, 'w', encoding='utf-8') as f_out:
                        f_out.write(output_content)
                    logging.info(f"Successfully wrote {output_format.upper()} data to: {output_path}")
                except IOError as e:
                    logging.error(f"Could not write to output file {output_path}: {e}")
                    sys.exit(1)
                except Exception as e:
                    logging.error(f"An unexpected error occurred writing file {output_path}: {e}")
                    sys.exit(1)
            else:
                print(output_content)
        else:
            logging.error(f"Failed to process file: {input_path}")
            sys.exit(1)

    # Directory Processing
    elif is_input_dir:
        default_output_dir_name = f"qhf_{output_format}_output"
        if not output_path:
            output_dir = default_output_dir_name
        else:
            output_dir = output_path

        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                logging.info(f"Created output directory: {output_dir}")
            except OSError as e:
                logging.error(f"Could not create output directory {output_dir}: {e}")
                sys.exit(1)
        elif not os.path.isdir(output_dir):
             logging.error(f"Specified output path '{output_dir}' exists but is not a directory.")
             sys.exit(1)

        file_count = 0
        success_count = 0
        failure_count = 0

        for filename in os.listdir(input_path):
            if filename.lower().endswith('.qhf'):
                file_count += 1
                infile_path = os.path.join(input_path, filename)
                header_info, messages = parse_qhf_file(infile_path)

                if header_info is not None and messages is not None:
                    output_content = ""
                    output_extension = f".{output_format}"
                    base_filename = os.path.splitext(filename)[0]
                    outfile_path = os.path.join(output_dir, f"{base_filename}{output_extension}")

                    try:
                        if output_format == 'json':
                            json_data = {
                                "uin": header_info.get('uin', 'N/A'),
                                "nickname": header_info.get('nickname', 'N/A'),
                                "messages": messages
                            }
                            output_content = json.dumps(json_data, indent=4, ensure_ascii=False)

                        elif output_format == 'txt':
                            formatted_entries = []
                            contact_name = header_info.get('nickname', 'Unknown Contact')
                            for msg in messages:
                                sender_name = "Me" if msg['is_outgoing'] else contact_name
                                timestamp_dt = datetime.datetime.fromisoformat(msg['timestamp_iso'])
                                formatted_entries.append(
                                    format_log_entry(sender_name, timestamp_dt, msg['text'])
                                )
                            output_content = '\n\n'.join(formatted_entries)

                        with open(outfile_path, 'w', encoding='utf-8') as f_out:
                            f_out.write(output_content)
                        logging.info(f"Successfully wrote {output_format.upper()} data to: {outfile_path}")
                        success_count += 1

                    except IOError as e:
                        logging.error(f"Could not write to output file {outfile_path}: {e}")
                        failure_count += 1
                    except TypeError as e:
                         logging.error(f"Error serializing data to JSON for {outfile_path}: {e}")
                         failure_count += 1
                    except Exception as e:
                         logging.error(f"An unexpected error occurred while processing/writing {outfile_path}: {e}")
                         failure_count += 1
                else:
                    logging.error(f"Failed to process file: {infile_path}")
                    failure_count += 1

        logging.info(f"--- Directory Processing Summary ---")
        logging.info(f"Output format: {output_format.upper()}")
        logging.info(f"Total .qhf files found: {file_count}")
        logging.info(f"Successfully converted: {success_count}")
        logging.info(f"Failed conversions: {failure_count}")
        if failure_count > 0:
            sys.exit(1)

if __name__ == '__main__':
    main()