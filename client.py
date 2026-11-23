import json
import os
import socket
from crypto_utils import (
    aes_decrypt,
    aes_encrypt,
    derive_session_key,
    recv_packet,
    rsa_encrypt,
    send_packet,
)

HOST = "127.0.0.1"
PORT = 65432


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print(f"[+] Підключено до сервера {HOST}:{PORT}")

        # Крок 1: Ініціювання рукостискання ("привіт" + client_random)
        client_random = os.urandom(16)
        send_packet(
            sock,
            {
                "step": "client_hello",
                "message": "привіт",
                "client_random": client_random.hex(),
            },
        )
        print(f"[Крок 1] Надіслано 'привіт', client_random = {client_random.hex()}")

        # Крок 2: Отримання ServerHello та відкритого ключа сервера
        srv_hello = recv_packet(sock)
        server_random = bytes.fromhex(srv_hello["server_random"])
        public_pem = srv_hello["public_key"]
        print(f"[Крок 2] Отримано '{srv_hello['message']}' та RSA public key.")
        print(f"         server_random = {srv_hello['server_random']}")

        # Крок 3: Пропуск перевірки CA для базового варіанту
        print("[Крок 3] Перевірка SSL-сертифіката в CA пропущена (базовий варіант).")

        # Крок 4: Генерація premaster та шифрування відкритим ключем сервера
        premaster = os.urandom(32)
        enc_premaster = rsa_encrypt(public_pem, premaster)
        send_packet(sock, {"step": "key_exchange", "encrypted_premaster": enc_premaster})
        print(f"[Крок 4] Надіслано зашифрований premaster = {premaster.hex()[:32]}...")

        # Крок 5: Генерація сеансового ключа
        session_key = derive_session_key(client_random, server_random, premaster)
        print(f"[Крок 5] Згенеровано session_key = {session_key.hex()}")

        # Крок 6: Обмін зашифрованими повідомленнями "готовий"
        send_packet(sock, aes_encrypt(session_key, "готовий"))
        print("[Крок 6] Надіслано зашифроване 'готовий' на сервер.")

        srv_ready_pkt = recv_packet(sock)
        srv_ready = aes_decrypt(session_key, srv_ready_pkt)
        print(f"[Крок 6] Від сервера отримано розшифроване: '{srv_ready}'")
        if srv_ready != "готовий":
            raise ValueError("Сервер не підтвердив готовність!")

        # Крок 7: Захищений канал передачі даних
        print("\n[Крок 7] Рукостискання успішно завершено! Захищений канал активний.")
        print("Введіть повідомлення для чату, '/file test.txt' для файлу або 'exit' для виходу.\n")

        while True:
            user_input = input("Ви > ").strip()
            if not user_input or user_input.lower() == "exit":
                break

            if user_input.startswith("/file "):
                path = user_input[6:].strip()
                if not os.path.isfile(path):
                    print(f"[!] Файл '{path}' не знайдено.")
                    continue
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                payload = json.dumps({"type": "file", "filename": path, "content": content}, ensure_ascii=False)
            else:
                payload = json.dumps({"type": "chat", "text": user_input}, ensure_ascii=False)

            send_packet(sock, aes_encrypt(session_key, payload))
            reply_pkt = recv_packet(sock)
            print(f"Сервер > {aes_decrypt(session_key, reply_pkt)}")


if __name__ == "__main__":
    main()