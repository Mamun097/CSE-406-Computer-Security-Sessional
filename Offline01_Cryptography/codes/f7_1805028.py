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
    # Connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        print('Connected to the server.')
        print('Enter "exit" to quit.')

        # Perform Diffie-Hellman key exchange
        p=int.from_bytes(client_socket.recv(128), 'big')
        g=int.from_bytes(client_socket.recv(128), 'big')
        b=diffie_hellman.generate_secret_key()
        B=diffie_hellman.generate_public_key(g,b,p)

        client_socket.sendall(B.to_bytes(128, 'big'))

        A = int.from_bytes(client_socket.recv(128), 'big')

        shared_secret_key = diffie_hellman.generate_shared_secret_key(A, b, p)

        # Encryption and decryption loop
        while True:
            # Encrypt and send a message to Bob
            message = input('Bob: ')
            if message == 'exit':
                break

            encrypted_message = aes.encrypt(message, shared_secret_key)        
            client_socket.sendall(encrypted_message.encode('utf-8'))

            # Receive and decrypt a message from Bob
            encrypted_response = client_socket.recv(1024)
            decrypted_response = aes.decrypt(encrypted_response, shared_secret_key)
            #convert decrypted_response from hex to ascii
            print("Alice:", convert_hex_to_ascii(decrypted_response))
    print('Connection closed.')

if __name__ == '__main__':
    main()