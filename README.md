# AvaddonDecryptor

This is a modification to the open-sourced tool created by Javier Yuste for decrypting 
files infected with Avaddon ransomware. 
The original method depended on different tools such as Sysinternals procdump, but 
we rely on another tool for the memory extraction. This version of the project
removes such dependencies, and works only with the strictly necessary.

## Instructions

The instructions will be similar to the original.

1) Generate a JSON file with the keys. The structure should be as follows:
```json
{
   "key1": {
      "algorithm": "AES",
      "size": 16
   },
   "key2": {
      "algorithm": "RSA",
      "size": 286
   }
}
```
   
2) If you have extracted multiple keys from Avaddon process, drop a file to the filesystem so Avaddon encrypts it. Keep the original file, 
so the script can check whether the key is valid or not (if decrypting it results
in the original file). Remember to pause the Avaddon process so it does not encrypt 
any further.

3) In case you extracted a single valid key, you can run the command as follows (no need for admin):

    `python3 main.py -k <keys_json> --folder <folder_to_decrypt>`

   
The script will also check whether the keys inputted are AES or not, and will
discard those which are not. In case there are multiple AES keys, the script will need 
an encrypted file and its unencrypted copy (specified via the arguments). In case 
a key outputs the original file when decrypting, that key will be considered the 
correct one.  
   
Please, check all available arguments with the `-h` option.

Note that decryption of the given folder is done recursively. So, to decrypt the whole system, the <folder_to_decrypt> value should be 'C:\\'

# Credits

Javier Yuste for providing the method of decryption of the Avaddon encrypted files.

Details of his work can be found in the [full article](https://www.sciencedirect.com/science/article/pii/S0167404821002121). Please cite as:

```
@article{Yuste2021Avaddon,
   title = {Avaddon ransomware: An in-depth analysis and decryption of infected systems},
   journal = {Computers & Security},
   volume = {109},
   pages = {102388},
   year = {2021},
   issn = {0167-4048},
   doi = {https://doi.org/10.1016/j.cose.2021.102388},
   url = {https://www.sciencedirect.com/science/article/pii/S0167404821002121},
   author = {Javier Yuste and Sergio Pastrana}
}
```
