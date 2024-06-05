from PIL import Image


def main():
    try:
        with open('input.txt', 'r') as file:
            # Read the contents of the file
            contents = file.read().splitlines()
    except FileNotFoundError:
        # Handle the case where the file doesn't exist
        print("The file was not found.")
        exit(1)
    except IOError:
        # Handle other I/O errors
        print("An I/O error occurred.")
        exit(1)

    if len(contents) != 4:
        print("Invalid input. You should enter mode, key, IV and path each on a different line.")
        exit(1)

    key = []
    IV = contents[2].zfill(16)
    path = contents[3]
    data, dimensions = read_image(path)

    # the key should be 128 bits, so if the input is less than that, zero pad from the left
    contents[1] = contents[1].zfill(32)
    for i in range(4):
        number = contents[1][i * 8:(i + 1) * 8]
        key.append(int(number, 16))

    # mode is ECB
    if contents[0].lower() == 'ecb':
        cipher = function_ECB(data, key, encrypt)
        save_image(cipher, "enc_ecb.bmp", dimensions)

        plaintext = function_ECB(cipher, key, decrypt)
        save_image(plaintext, "dec_ecb.bmp", dimensions)

    elif contents[0].lower() == 'cbc':
        cipher = encrypt_CBC(data, key, IV)
        save_image(cipher, "enc_cbc.bmp", dimensions)

        plaintext = decrypt_CBC(cipher, key)
        save_image(plaintext, "dec_cbc.bmp", dimensions)

    else:
        print("Invalid mode entered.")
        exit(1)


def read_image(path):
    # Open the image file
    try:
        with Image.open(path, 'r') as image:
            # convert to gray scale
            image = image.convert("L")
    except FileNotFoundError:
        # Handle the case where the file doesn't exist
        print("The image was not found.")
        exit(1)
    except IOError:
        # Handle other I/O errors
        print("An I/O error occurred when reading the image.")
        exit(1)

    # Convert the image to grayscale
    image = image.convert("L")

    # Get the dimensions of the image
    width, height = image.size

    # Load pixel data from the image
    pixel_data = list(image.getdata())

    # Convert pixel values to unicode characters
    unicode_characters = [chr(pixel) for pixel in pixel_data]

    # Convert the list of ASCII characters to a string
    unicode_string = ''.join(unicode_characters)
    return unicode_string, (width, height)


def save_image(data, name, dimensions):
    # Convert the unicode string back to a list of pixel values
    pixel_values = list(map(ord, data))

    # Create an image from the pixel values
    width = dimensions[0]
    height = dimensions[1]

    print(f"width * height : {width * height}")
    print(f"length of data : {len(data)}")

    if len(data) > width * height:
        height += 1

    elif len(data) < width * height:
        height -= 1

    image = Image.new("L", (width, height))
    image.putdata(pixel_values)

    # Save or display the image
    image.save(name)  # Save the image
    image.show()  # Display the image


def decrypt_CBC(data, key):
    """
    Decrypts data using the Cipher Block Chaining (CBC) mode.

    Parameters:
    data (str): The input ciphertext to be decrypted.
    key (list): A list of four 32-bit integers used as the decryption key.

    Returns:
    str: The resulting plaintext after decryption.
    """

    plaintext = ''
    prev = data[0:8]  # Initialize previous ciphertext block to the IV
    prev = map(lambda x: hex(ord(x))[2:] if len(hex(ord(x))[2:]) > 1 else "0" + hex(ord(x))[2:], prev)
    prev = ''.join(prev)

    # Process each ciphertext block (excluding the IV)
    for i in range(1, len(data) // 8):
        next = data[i * 8:(i + 1) * 8]

        # Convert each character in the block to its hex representation
        next = map(lambda x: hex(ord(x))[2:] if len(hex(ord(x))[2:]) > 1 else "0" + hex(ord(x))[2:], next)
        next = ''.join(next)

        # Decrypt the current block and XOR with the previous block
        message = int(decrypt(next, key), 16) ^ int(prev, 16)
        message = hex(message)[2:].zfill(16)  # Convert result back to hex string and ensure 16 characters
        message = ''.join(
            [chr(int(message[i:i + 2], 16)) for i in range(0, len(message), 2)])  # Convert hex to characters
        plaintext = plaintext + message  # Append the decrypted message to the plaintext
        prev = next  # Update the previous block for the next iteration

    return plaintext


def encrypt_CBC(data, key, initial_vector):
    """
    Encrypts data using the Cipher Block Chaining (CBC) mode with the given initial vector.

    Parameters:
    data (str): The input data to be encrypted.
    key (list): A list of four 32-bit integers used as the encryption key.
    initial_vector (str): The initial vector (IV) used in CBC mode.

    Returns:
    str: The resulting ciphertext after processing with CBC mode.
    """

    prev = initial_vector
    ciphertext = initial_vector

    # Pad data with null characters to make its length a multiple of 8
    if len(data) % 8 != 0:
        data = data + ("\0" * (8 - len(data) % 8))

    # Convert initial vector to hexadecimal representation
    prev = map(lambda x: hex(ord(x))[2:] if len(hex(ord(x))[2:]) > 1 else "0" + hex(ord(x))[2:], prev)
    prev = ''.join(prev)

    # Process each 8-byte block
    for i in range(0, len(data) // 8):
        message = data[i * 8:(i + 1) * 8]

        # Convert each character in the block to its hex representation
        plaintext = map(lambda x: hex(ord(x))[2:] if len(hex(ord(x))[2:]) > 1 else "0" + hex(ord(x))[2:], message)
        plaintext = ''.join(plaintext)

        # XOR plaintext with previous block (or initial vector for the first block)
        message_temp = int(plaintext, 16) ^ int(prev, 16)

        # Encrypt the XOR result using TEA
        prev = encrypt(hex(message_temp)[2:], key, 32)

        # Convert the hex result back to a string
        result_string = ''.join([chr(int(prev[i:i + 2], 16)) for i in range(0, len(prev), 2)])

        # Append the result to the ciphertext
        ciphertext = ciphertext + result_string

    return ciphertext


def function_ECB(data, key, function):
    """
    Encrypts or decrypts data using the Electronic Codebook (ECB) mode with the given function.

    Parameters:
    data (str): The input data to be encrypted or decrypted.
    key (list): A list of four 32-bit integers used as the encryption/decryption key.
    function (callable): The function to perform the encryption or decryption (e.g., encrypt or decrypt).

    Returns:
    str: The resulting ciphertext or plaintext after processing with ECB mode.
    """

    ciphertext = ''

    # Pad data with null characters to make its length a multiple of 8
    data = data + ("\0" * (8 - len(data) % 8))

    # Process each 8-byte block
    for i in range(len(data) // 8):
        message = data[i * 8:i * 8 + 8]

        # Convert each character to its hex representation
        plaintext = map(lambda x: hex(ord(x))[2:] if len(hex(ord(x))[2:]) > 1 else "0" + hex(ord(x))[2:], message)
        plaintext = ''.join(plaintext)

        # Encrypt or decrypt the block
        ciphertext_temp = function(plaintext, key, 32)

        # Convert the hex result back to a string
        result_string = ''.join([chr(int(ciphertext_temp[i:i + 2], 16)) for i in range(0, len(ciphertext_temp), 2)])

        # Append the result to the ciphertext
        ciphertext = ciphertext + result_string

    return ciphertext


def encrypt(plaintext, key, rounds=32):
    """
    Encrypts the plaintext using the Tiny Encryption Algorithm (TEA).

    Parameters:
    plaintext (str): The plaintext to be encrypted, represented as a hexadecimal string.
    key (list): A list of four 32-bit integers used as the encryption key.
    rounds (int): The number of rounds of encryption to perform (default is 32).

    Returns:
    str: The ciphertext resulting from the encryption process, represented as a hexadecimal string.
    """

    # Split the plaintext into left and right 32-bit halves
    left = int(plaintext, 16) >> 32
    right = int(plaintext, 16) % 2 ** 32

    # Constant delta value used in TEA
    delta = 0x9E3779B9
    sum = 0

    # Perform the encryption rounds
    for i in range(rounds):
        sum = (sum + delta) % 2 ** 32  # Keep sum within 32 bits
        left = (left + (((right << 4) + key[0]) ^ (right + sum) ^ ((right >> 5) + key[1]))) % 2 ** 32
        right = (right + (((left << 4) + key[2]) ^ (left + sum) ^ ((left >> 5) + key[3]))) % 2 ** 32

    # Convert the left and right halves back to hex strings
    # Zero pad the right and left results if their length is less than 8 (32 bits)
    right = hex(right)[2:].zfill(8)
    left = hex(left)[2:].zfill(8)

    # Concatenate the left and right halves to form the final ciphertext
    ciphertext = left + right

    return ciphertext


def decrypt(ciphertext, key, rounds=32):
    """
    Decrypts the ciphertext using the Tiny Encryption Algorithm (TEA).

    Parameters:
    ciphertext (str): The ciphertext to be decrypted, represented as a hexadecimal string.
    key (list): A list of four 32-bit integers used as the decryption key.
    rounds (int): The number of rounds of decryption to perform (default is 32).

    Returns:
    str: The plaintext resulting from the decryption process, represented as a hexadecimal string.
    """

    # Split the ciphertext into left and right 32-bit halves
    left = int(ciphertext, 16) >> 32
    right = int(ciphertext, 16) % 2 ** 32

    # Constant delta value used in TEA
    delta = 0x9E3779B9
    sum = (delta * rounds) % 2 ** 32  # Initial sum value

    # Perform the decryption rounds
    for i in range(rounds):
        right = (right - (((left << 4) + key[2]) ^ (left + sum) ^ ((left >> 5) + key[3]))) % 2 ** 32
        left = (left - (((right << 4) + key[0]) ^ (right + sum) ^ ((right >> 5) + key[1]))) % 2 ** 32
        sum = (sum - delta) % 2 ** 32  # Keep sum within 32 bits

    # Convert the left and right halves back to hex strings
    # Zero pad the right and left results if their length is less than 8 (32 bits)
    right = hex(right)[2:].zfill(8)
    left = hex(left)[2:].zfill(8)

    # Concatenate the left and right halves to form the final plaintext
    plaintext = left + right

    return plaintext


if __name__ == '__main__':
    main()
