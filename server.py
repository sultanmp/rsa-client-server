import socket
import base64
from rsa import RSA


#initail permutation
ip_table = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# PC1 permutation table
pc1_table = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
]

# Define the left shift schedule for each round
shift_schedule = [1, 1, 2, 2,
                  2, 2, 2, 2,
                  1, 2, 2, 2,
                  2, 2, 2, 1]

# PC2 permutation table
pc2_table = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

# Expansion box for DES
e_box_table = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# S-box tables for DES
s_boxes = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 9, 2, 0, 14],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 6, 3, 11, 5]
    ]
]

# P-box permutation table
p_box_table = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

# Inverse initial permutation table
ip_inverse_table = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

def hex_to_bin(hex_string):
    return ''.join(format(int(c, 16), '04b') for c in hex_string)

def str_to_bin(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bin_to_str(binary):
    return ''.join(chr(int(binary[i:i + 8], 2)) for i in range(0, len(binary), 8))

def permute(input_bits, permutation_table):
    return ''.join(input_bits[bit - 1] for bit in permutation_table)

def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]

def generate_round_keys(key):
    key = hex_to_bin(key)
    key = permute(key, pc1_table)
    
    left_key = key[:28]
    right_key = key[28:]
    
    round_keys = []
    
    for shifts in shift_schedule:
        left_key = left_shift(left_key, shifts)
        right_key = left_shift(right_key, shifts)
        round_key = permute(left_key + right_key, pc2_table)
        round_keys.append(round_key)

    return round_keys

def f_function(right_half, round_key):
    expanded_half = permute(right_half, e_box_table)
    xored = ''.join('1' if a != b else '0' for a, b in zip(expanded_half, round_key))
    
    sbox_output = ''
    for i in range(8):
        row = int(xored[i * 6] + xored[i * 6 + 5], 2)
        col = int(xored[i * 6 + 1:i * 6 + 5], 2)
        sbox_value = s_boxes[i][row][col]
        sbox_output += format(sbox_value, '04b')

    permuted_output = permute(sbox_output, p_box_table)
    
    return permuted_output

def des_encrypt(plaintext, key):
    # Initial permutation
    initial_permutation = permute(plaintext, ip_table)
    
    # Generate round keys from the given key
    round_keys = generate_round_keys(key)

    # Split the initial permutation into left and right halves
    left_half = initial_permutation[:32]
    right_half = initial_permutation[32:]

    # Iterate over each round of the DES algorithm
    for round_key in round_keys:
        # Apply the f function to the right half and the round key
        temp = f_function(right_half, round_key)
        
        # XOR the result with the left half
        new_left_half = ''.join('1' if a != b else '0' for a, b in zip(left_half, temp))
        
        # Update the halves for the next round
        left_half, right_half = right_half, new_left_half

    # Combine the final left and right halves
    combined = left_half + right_half

    # Perform the final permutation
    ciphertext = permute(combined, ip_inverse_table)
    
    return ciphertext

def des_decrypt(ciphertext, key):
    initial_permutation = permute(ciphertext, ip_table)
    round_keys = generate_round_keys(key)

    left_half = initial_permutation[:32]
    right_half = initial_permutation[32:]

    for round_key in reversed(round_keys):
        temp = left_half
        left_half = ''.join('1' if a != b else '0' for a, b in zip(right_half, f_function(left_half, round_key)))
        right_half = temp

    final_output = left_half + right_half
    plaintext = permute(final_output, ip_inverse_table)

    return plaintext

def decrypt_des_key(encrypted_key, private_key):
    try:
        encrypted_key = list(map(int, encrypted_key.split(',')))
        decrypted_key_str = RSA.decrypt(encrypted_key, private_key)
        print(f"Decrypted key string: '{decrypted_key_str}'")  # Debug statement with quotes

        # Strip any unwanted characters
        decrypted_key_str = decrypted_key_str.strip()
        print(f"Stripped decrypted key string: '{decrypted_key_str}'")  # Debug statement with quotes

        # Check if the decrypted key string is empty
        if not decrypted_key_str:
            print("Decrypted key string is empty.")
            return None

        # Convert the hexadecimal string back to an integer
        des_key = int(decrypted_key_str, 16)
        print(f"Decrypted integer DES key: {des_key}")
        return des_key
    except ValueError as e:
        print(f"Error converting decrypted key to integer: {e}")
        return None

def des_decrypt(encrypted_text, key):
    # Dummy decryption function for demonstration
    # Replace this with the actual DES decryption implementation
    return "decrypted text"

def bin_to_str(binary_string):
    # Convert a binary string back to ASCII text
    ascii_text = ''.join([chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8)])
    return ascii_text

def str_to_bin(text):
    # Convert ASCII text to a binary string
    binary_string = ''.join(format(ord(c), '08b') for c in text)
    return binary_string

def des_encrypt(plaintext, key):
    # Dummy encryption function for demonstration
    # Replace this with the actual DES encryption implementation
    return "encrypted text"

def main():
    host = 'localhost'
    port = 8080

    public_key, private_key = RSA.generate_keys()
    print(f"Public key (send to Public Key Authority):\n{public_key}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server listening on port {port} ...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        try:
            data = conn.recv(1024).decode('utf-8')
            print(f"Data received: {data}")
            encrypted_key, text = data.split(',', 1)

            des_key = decrypt_des_key(encrypted_key, private_key)
            if des_key is None:
                print("Failed to decrypt DES key.")
                continue

            print(f"Decrypted DES key: {des_key}")

            if all(c in '01' for c in text):
                plaintext_bin = des_decrypt(text, des_key)
                plaintext = bin_to_str(plaintext_bin)
                conn.sendall(plaintext.encode('utf-8'))
            else:
                plaintext_bin = str_to_bin(text)
                if len(plaintext_bin) % 64 != 0:
                    plaintext_bin = plaintext_bin.ljust((len(plaintext_bin) // 64 + 1) * 64, '0')
                ciphertext = des_encrypt(plaintext_bin, des_key)
                conn.sendall(ciphertext.encode('utf-8'))
            print("Processed message sent back to client.")  # Debug statement

        except Exception as e:
            print(f"An error occurred: {e}")

        finally:
            conn.close()
            print("Connection closed.")  # Debug statement

if __name__ == "__main__":
    main()










