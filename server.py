import socket
import json
from rsa_helper import (
    generate_keypair,
    rsa_encrypt,
    rsa_decrypt,
    generate_random_des_key,
    encrypt_list_to_string,
    string_to_encrypted_list,
    des_encrypt,
    des_decrypt
)


def is_hex_string(s):
    """Cek apakah string valid hex."""
    if not s:
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


def main():
    print("=" * 50)
    print("--- SERVER (Device 1) with RSA Key Exchange ---")
    print("=" * 50)

    HOST = "0.0.0.0"
    PORT = 8888

    print("\n[Generating RSA key pair for Server...]")
    public_key, private_key = generate_keypair(bits=1024)
    e, n = public_key
    print("[Server Public Key Generated]")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    print(f"\n[Server listening on {HOST}:{PORT}]")
    print("Waiting for Device 2 (Client) to connect...")
    conn, addr = server_socket.accept()
    print(f"\n[Device 2 connected from {addr}]")

    with conn:
        # ----- PUBLIC KEY EXCHANGE -----
        print("\n[Exchanging public keys...]")

        # Send server public key
        server_pubkey_data = json.dumps({"e": e, "n": n})
        conn.sendall((server_pubkey_data + "\n").encode())
        print("[Server public key sent to Client]")

        # Receive client public key
        client_pubkey_json = conn.recv(4096).decode().strip()
        client_pubkey = json.loads(client_pubkey_json)
        client_public_key = (client_pubkey["e"], client_pubkey["n"])
        print("[Client public key received]")

        print("\n" + "=" * 50)
        print("[Key exchange complete! Ready for secure communication]")
        print("=" * 50)

        # ----- MAIN MENU LOOP -----
        while True:
            print("\n" + "-" * 50)
            print("Please choose an option:")
            print("  1. Encrypt and Send a message (auto-generate DES key)")
            print("  2. Receive and Decrypt a message")
            print("  3. Exit")
            print("-" * 50)

            choice = input("Enter your choice (1, 2, or 3): ")

            # =====================================================
            # 1. SEND MESSAGE (ENCRYPT)
            # =====================================================
            if choice == "1":
                plaintext = input("\nEnter the message to encrypt: ")

                try:
                    des_key = generate_random_des_key()
                    print(f"\n[Auto-generated DES key: '{des_key}']")

                    ciphertext_hex = des_encrypt(des_key, plaintext)
                    print(f"[DES encrypted message: {ciphertext_hex}]")

                    encrypted_key = rsa_encrypt(client_public_key, des_key)
                    encrypted_key_str = encrypt_list_to_string(encrypted_key)

                    print(f"[RSA encrypted DES key (first 5 values): {encrypted_key[:5]}...]")

                    package = json.dumps({
                        "encrypted_key": encrypted_key_str,
                        "encrypted_message": ciphertext_hex
                    })

                    conn.sendall((package + "\n").encode())
                    print("\n[✓ Message sent successfully!]")

                except Exception as e:
                    print(f"\n[✗ Error during encryption: {e}]")

            # =====================================================
            # 2. RECEIVE MESSAGE (DECRYPT)
            # =====================================================
            elif choice == "2":
                print("\n[Waiting to receive message from Device 2...]")

                try:
                    received = conn.recv(8192).decode().strip()
                    if not received:
                        print("[Connection closed by client.]")
                        break

                    data = json.loads(received)
                    encrypted_key_str = data["encrypted_key"]
                    encrypted_message_hex = data["encrypted_message"]

                    print("[Received encrypted DES key and message]")

                    encrypted_key_list = string_to_encrypted_list(encrypted_key_str)
                    des_key = rsa_decrypt(private_key, encrypted_key_list)

                    print(f"[Decrypted DES key: '{des_key}']")

                    if not is_hex_string(encrypted_message_hex):
                        print("  Error: Received data is not valid hex. Cannot decrypt.")
                        continue

                    decrypted_text = des_decrypt(des_key, encrypted_message_hex)

                    print("\n[✓ Message decrypted successfully!]")
                    print(f"   Decrypted message: '{decrypted_text}'")

                except Exception as e:
                    print(f"\n[✗ Error during decryption: {e}]")

            # =====================================================
            # 3. EXIT
            # =====================================================
            elif choice == "3":
                print("\n[Exiting program...]")
                break
            else:
                print("\n[Invalid choice. Please enter 1, 2, or 3.]")

    server_socket.close()
    print("\n[Server socket closed. Goodbye!]")


if __name__ == "__main__":
    main()
