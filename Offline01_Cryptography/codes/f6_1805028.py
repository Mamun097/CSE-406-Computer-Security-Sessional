import socket
import f4_1805028 as aes
import f5_1805028 as diffie_hellman

HOST = 'localhost'  
PORT = 33445       

def convert_hex_to_ascii(hex_string):
    ascii_string = ""
    for i in range(0, len(hex_string), 2):
        hex_value = hex_string[i:i+2]
        ascii_string += chr(int(hex_value, 16))
    return ascii_string

def main():
    # Create a server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print('Waiting for a connection...')

        # Accept a client connection
        client_socket, address = server_socket.accept()
        print(f'Connected to {address}.')
        print('Enter "exit" to quit.')

        # Perform Diffie-Hellman key exchange
        p=diffie_hellman.generate_prime_number(128)
        g=diffie_hellman.generate_primitive_root(p)
        a=diffie_hellman.generate_secret_key()
        A=diffie_hellman.generate_public_key(g,a,p)

        client_socket.sendall(p.to_bytes(128, 'big'))
        client_socket.sendall(g.to_bytes(128, 'big'))
        client_socket.sendall(A.to_bytes(128, 'big'))

        B = int.from_bytes(client_socket.recv(128), 'big')

        shared_secret_key = diffie_hellman.generate_shared_secret_key(B, a, p)

        # Encryption and decryption loop
        while True:
            # Receive and decrypt a message from Alice
            encrypted_message = client_socket.recv(1024)
            decrypted_message = aes.decrypt(encrypted_message, shared_secret_key)
            print("Bob:", convert_hex_to_ascii(decrypted_message))

            # Encrypt and send a response to Alice
            response = input('Alice: ')
            if response == 'exit':
                break

            encrypted_response = aes.encrypt(response, shared_secret_key)
            client_socket.sendall(encrypted_response.encode('utf-8'))

    print('Connection closed.')


if __name__ == '__main__':
    main()
