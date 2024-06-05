# Image Encryption and Decryption using TEA

This program encrypts and decrypts images using the Tiny Encryption Algorithm (TEA) in either ECB (Electronic Codebook) 
or CBC (Cipher Block Chaining) mode. The user provides input via a file named `input.txt`, and the program processes 
the image accordingly.

## Input Format

The input file `input.txt` should be located in the same directory as the script and have the following format:

1. The first line contains the mode: `ECB` or `CBC`.
2. The second line contains the 128-bit key, entered as a hex string (32 hex-digits).
3. The third line contains the initialization vector (IV) for CBC, entered as a unicode string (8 characters, ignored for ECB).
4. The fourth line contains the name of the image to be encrypted and decrypted (e.g., `Image.png`).

## Key Notes

-  The key and IV inputs that are shorter than their desired lengths are zero-padded from the left.
-  Input images that do not form full blocks are zero-padded from the right to match the block size.

## Output

The resulting encrypted and decrypted images are saved in the same directory as the script with filenames formatted as `enc_{modeName}.{format}` and `dec_{modeName}.{format}` respectively.

## Dependencies

- Python 3.x
- Pillow (PIL Fork) - for image processing

You can install the required packages using pip:

```bash
pip install pillow
```

## Usage

1. Ensure you have input.txt in the same directory as the script, formatted as described in the Input Format section.
2. Run the script:

