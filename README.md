# Image Encryption and Decryption using TEA

This program encrypts and decrypts images using the Tiny Encryption Algorithm (TEA) in either ECB (Electronic Codebook) 
or CBC (Cipher Block Chaining) mode. The user provides input via a file named `input.txt`, and the program processes 
the image accordingly.

## Input Format

The input file `input.txt` should be located in the same directory as the script and have the following format:

1. The first line contains the mode: `ECB` or `CBC`.
2. The second line contains the 128-bit key, entered as a hex string (32 hex-digits).
3. The third line contains the initialization vector (IV) for CBC, entered as a unicode string (ignored for ECB).
4. The fourth line contains the name of the image to be encrypted and decrypted (e.g., `Image.png`).

## Output

The resulting encrypted and decrypted images are saved in the same directory as the script with filenames formatted as `enc_{modeName}.{format}` and `dec_{modeName}.{format}` respectively.

## Dependencies

- Python 3.x
- Pillow (PIL Fork) - for image processing

You can install the required packages using pip:

```bash
pip install pillow pycryptodome
