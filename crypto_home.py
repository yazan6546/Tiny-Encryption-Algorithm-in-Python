import functools
import math

from Crypto.Cipher import AES
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

        number = contents[1][i*8:(i+1)*8]
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

    else :
        print("Invalid mode entered.")
        exit(1)




def show_menu ():
    print("-------Encrypt or Decrypt Menu-------\n")
    print("1. Encrypt and Decrypt regular text")
    print("2. Encrypt and Decrypt images")
    print("3. Exit\n")

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
    plaintext = ''
    prev = data[0:8]
    prev = map(lambda x: hex(ord(x))[2::] if len(hex(ord(x))[2::]) > 1 else "0" + hex(ord(x))[2::], prev)
    prev = ''.join(prev)

    for i in range(1, len(data) // 8):
        next = data[i * 8:(i + 1) * 8]

        # convert unicode string into a hexadecimal string
        next = map(lambda x: hex(ord(x))[2::] if len(hex(ord(x))[2::]) > 1 else "0" + hex(ord(x))[2::], next)
        next = ''.join(next)

        message = int(decrypt(next, key), 16) ^ int(prev, 16)
        message = hex(message)[2::].zfill(16)
        message = ''.join([chr(int(message[i:i + 2], 16)) for i in range(0, len(message), 2)])
        plaintext = plaintext + message
        prev = next

    return plaintext


def encrypt_CBC(data, key, initial_vector):
    prev = initial_vector
    ciphertext = initial_vector

    if len(data) % 8 != 0:
        data = data + ("\0" * (8 - len(data) % 8))

    prev = map(lambda x: hex(ord(x))[2::] if len(hex(ord(x))[2::]) > 1 else "0" + hex(ord(x))[2::], prev)
    prev = ''.join(prev)

    for i in range(0, len(data) // 8):
        message = data[i * 8:(i + 1) * 8]

        plaintext = map(lambda x: hex(ord(x))[2::] if len(hex(ord(x))[2::]) > 1 else "0" + hex(ord(x))[2::], message)
        plaintext = ''.join(plaintext)

        message_temp = int(plaintext, 16) ^ int(prev, 16)
        prev = encrypt(hex(message_temp)[2::], key, 32)
        result_string = ''.join([chr(int(prev[i:i + 2], 16)) for i in range(0, len(prev), 2)])
        ciphertext = ciphertext + result_string

    return ciphertext


def function_ECB(data, key, function):
    ciphertext = ''

    data = data + ("\0" * (8 - len(data) % 8))

    for i in range(len(data) // 8):
        message = data[i * 8:i * 8 + 8]
        plaintext = map(lambda x: hex(ord(x))[2::] if len(hex(ord(x))[2::]) > 1 else "0" + hex(ord(x))[2::], message)
        plaintext = ''.join(plaintext)
        ciphertext_temp = function(plaintext, key, 32)
        result_string = ''.join([chr(int(ciphertext_temp[i:i + 2], 16)) for i in range(0, len(ciphertext_temp), 2)])
        ciphertext = ciphertext + result_string
    return ciphertext


def encrypt(plaintext, key, rounds=32):
    left = int(plaintext, 16) >> 32
    right = int(plaintext, 16) % 2 ** 32
    delta = 0x9E3779B9
    sum = 0
    for i in range(0, rounds):
        sum = sum + delta
        left = (left + (((right << 4) + key[0]) ^ (right + sum) ^ ((right >> 5) + key[1]))) % 2 ** 32
        right = (right + (((left << 4) + key[2]) ^ (left + sum) ^ ((left >> 5) + key[3]))) % 2 ** 32

    # zero pad the right and left results if their length is less than 8 (32 bits)
    right = hex(right)[2::].zfill(8)
    left = hex(left)[2::].zfill(8)

    ciphertext = left + right
    return ciphertext


def decrypt(ciphertext, key, rounds=32):
    left = int(ciphertext, 16) >> 32
    right = int(ciphertext, 16) % 2 ** 32
    delta = 0x9E3779B9
    sum = (delta << 5)
    for i in range(0, rounds):
        right = (right - (((left << 4) + key[2]) ^ (left + sum) ^ ((left >> 5) + key[3]))) % 2 ** 32
        left = (left - (((right << 4) + key[0]) ^ (right + sum) ^ ((right >> 5) + key[1]))) % 2 ** 32
        sum = sum - delta

    right = hex(right)[2::].zfill(8)
    left = hex(left)[2::].zfill(8)

    plaintext = left + right

    return plaintext


if __name__ == '__main__':
    main()
