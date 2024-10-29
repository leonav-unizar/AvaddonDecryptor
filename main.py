import argparse
import filecmp
import mmap
import subprocess
import json
import struct
import os
import shutil
import logging
import time

logging.basicConfig(format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%m/%d %I:%M:%S', level=logging.INFO)
import sys

script_dir = os.path.dirname(os.path.abspath(__file__))

def get_signature_data(file):
    with open(file, "r+b") as f:
        # Memory-map the file, size 0 means whole file
        mm = mmap.mmap(f.fileno(), 0)
        signature = mm[-24:]
        mm.close()
    # Original file size written in the signature
    original_file_size = int.from_bytes(signature[0:8], byteorder='little')
    harcoded_signature = struct.unpack('<L', signature[16:20])[0]
    # Those are bytes, we need to convert them to integer
    print(f"Signature: {signature}")
    print(f"Original file size unpacked: {original_file_size} ({hex(original_file_size)})")
    print(f"Hardcoded signature: {hex(harcoded_signature)}")

    data = dict()
    data['original_size'] = original_file_size
    return data


def remove_signature(file):
    # Remove signature in the copy
    file_size = os.stat(file).st_size
    print(f"Size of the encrypted file with signature: {file_size}")
    with open(file, "r+b") as f:
        # Remove the signature
        f.truncate(
            file_size - 24 - 512)  # The ransom appends 512 bytes after encrypting, which correspond to the victim ID
    print(f"Size of the encrypted file without signature: {os.stat(file).st_size}")
    return file


def decrypt_file(file, key):
    print(f"\tDecrypting file {file} with key {key}")
    with open("key_bytes", 'wb') as f:
        f.write(key)
    key_path = os.path.abspath("key_bytes")
    # Invoke C++ program, which decrypts a specified file with a given key
    abs_path = os.path.abspath(file)
    filename, file_extension = os.path.splitext(abs_path)
    print(f"\tDecrypting {abs_path}")
    subprocess.run(["DecryptFile.exe", abs_path, filename, key_path], stdout=subprocess.PIPE)
    if os.stat(abs_path).st_size > 0x100000:
        with open(abs_path, "r+b") as f:
            mm = mmap.mmap(f.fileno(), 0)
            with open(filename, "r+b") as f2:
                # Memory-map the file, size 0 means whole file
                mm.seek(0x100000)
                f2.seek(0, 2)
                while mm.tell() < mm.size() and (mm.size() - mm.tell()) > 0x2000:
                    f2.write(mm.read(0x2000))
                if mm.tell() < mm.size():
                    f2.write(mm.read(mm.size() - mm.tell()))
            mm.close()
    return filename


def decrypt_whole_system(rootdir, key, encrypted_file_extension):
    """
    This function recursively decrypts the given folder given a key and a file extension known for the encrypted files.
    @param rootdir: The root directory with the files to be decrypted. Use C:/ to decrypt the whole filesystem
    @param key: The decryption key that will be used for decrypting the files
    @param encrypted_file_extension: the extension of the files that were been encrypted, e.g., .avdn
    """
    print("Decrypting whole system")
    total_files = 0
    total_encrypted_files = 0
    start_time = time.perf_counter()
    for subdir, dirs, files in os.walk(os.path.abspath(rootdir)):
        for file in files:
            total_files += 1
            file_path = os.path.abspath(os.path.join(subdir, file))
            if (file_path.endswith(encrypted_file_extension)) and "$Recycle.Bin" not in file_path:
                try:
                    print(f"> Found file {file_path}")
                    total_encrypted_files += 1
                    data = get_signature_data(file_path)
                    print(f"\tRemoving signature")
                    data['encrypted_truncated_file'] = remove_signature(file_path)
                    print("\tDecrypting file")
                    decrypted_file = decrypt_file(data['encrypted_truncated_file'], key)
                    print(f"\tTruncating to {data['original_size']}")
                    with open(decrypted_file, "r+b") as f:
                        f.truncate(data["original_size"])
                    os.remove(file_path)
                except OSError:
                    print("Permissions denied?")
                    pass

    print(f"\n--- SUMMARY ---"
          f"\nTotal files: {total_files}"
          f"\nDecrypted files: {total_encrypted_files}"
          f"\nTime: {time.perf_counter() - start_time}")


def main(args):

    # Read file with potential keys
    with open(args.keys, 'r') as file:
        json_data = json.load(file)

    # Search for the AES keys
    possible_keys = list()
    for i in json_data:
        print(i)
        if json_data[i]["algorithm"] == "AES":
            possible_keys.append(bytes.fromhex(i))

    if len(possible_keys) == 0:
        print(" [x] No valid keys were provided")
        exit(-1)
    elif len(possible_keys) == 1:
        print(" [!] Only one key was provided. Directly trying to decrypt")
        decrypt_whole_system(args.folder, possible_keys[0], args.extension)
    else:
        print(" [!] Found multiple keys. Trying to find which one is valid")
        if not args.original or not args.file:
            print(" [x] For this option is necessary to provide a file encrypted by Avaddon and its unencrypted version."
                  "Please check script arguments for more information")
            exit(-1)

        original_file = os.path.abspath(args.original)
        encrypted_file = os.path.abspath(args.file)
        _, file_extension = os.path.splitext(encrypted_file)

        # Get original file size and perform initial truncate
        shutil.copy(encrypted_file, f"{encrypted_file}.backup_copy")
        data = get_signature_data(encrypted_file)
        data['encrypted_truncated_file'] = remove_signature(encrypted_file)
        # Try each key till success
        success = False
        i = 0
        possible_keys = list(dict.fromkeys(possible_keys))
        while not success and i < len(possible_keys):
            # Decrypt file
            decrypted_file = decrypt_file(data['encrypted_truncated_file'], possible_keys[i])
            # Truncate to original size
            with open(decrypted_file, "r+b") as f:
                f.truncate(data["original_size"])
            # Compare with the original file
            success = filecmp.cmp(decrypted_file, original_file, shallow=True)
            if not success:
                i += 1

        if success:
            print(f"[SUCCESS] Found the correct symmetric key: {possible_keys[i]}")
            os.remove(data['encrypted_truncated_file'])
            decrypt_whole_system(args.folder, possible_keys[i], file_extension)
        else:
            shutil.copy(f"{encrypted_file}.backup_copy", encrypted_file)
            os.remove(f"{encrypted_file}.backup_copy")
            print("[FAIL] Did not find the correct symmetric key")


if __name__ == '__main__':
    description = """
    	Decrypts Avaddon encrypted files in a specific folder. 
    	The decryption is done recursively, which means that it may decrypt the whole system if the root path is C:\\.
    	To do this, three files are needed:
    	    1) a JSON with all keys extracted from Avaddon
    	    2) a folder with the files to decrypt
    	    3) if there are multiple possible AES keys, an encrypted file and its unencrypted version
    	The encrypted file is decrypted with all the valid session keys found in the JSON file.
    	If decrypting the encrypted file with one of such keys results in a file that is identical to the original one, 
    	it means that we have recovered the session key.
    	If that is the case, we proceed to decrypt all the encrypted files in the specified folder.
    	IMPORTANT: BACKUP YOUR SYSTEM BEFORE LAUNCHING THE DECRYPTOR.
    	THIS TOOL IS PROVIDED AS A PROOF OF CONCEPT, WITHOUT ANY WARRANTY.
    	"""

    arg_parser = argparse.ArgumentParser(description=description)
    arg_parser.add_argument('-f', '--encfile', type=str, metavar='FILE', required=False, dest='file',
                            help='Encrypted file')
    arg_parser.add_argument('-o', '--original', type=str, metavar='FILE', required=False, dest='original',
                            help='Original version of the encrypted file file')
    arg_parser.add_argument('-k', '--keys', type=str, required=True, help="JSON file with the keys",
                            default="keys.json")
    arg_parser.add_argument('-e', '--extension', type=str, required=False, default=".avdn",
                            help="File extension of the encrypted files. Defaults to '.avdn'. If --encfile option is "
                                 "present, it will be grabbed from the specified file, and this option will be ignored")
    arg_parser.add_argument('--folder', type=str, dest='folder', required=False, help='Folder to decrypt recursively', default="C:/")

    main(args=arg_parser.parse_args())
