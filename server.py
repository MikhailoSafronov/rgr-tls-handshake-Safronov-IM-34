import json
import os
import socket
from crypto_utils import (
    aes_decrypt,
    aes_encrypt,
    derive_session_key,
    generate_rsa_keys,
    recv_packet,
    rsa_decrypt,
    send_packet,
)

HOST = "127.0.0.1"
PORT = 65432


def handle_client(conn: socket.socket, addr) -> None:
    print(f"\n[+] Підключився клієнт: {addr}")

    # Крок 1: Отримуємо ClientHello ("привіт" + client_random)
    hello = recv_packet(conn)
    client_random = bytes.fromhex(hello["client_random"])
    print(f"[Крок 1] Отримано від клієнта: '{hello['message']}'")
    print(f"         client_random = {hello['client_random']}")

    # Крок 2: Генеруємо RSA-ключі та надсилаємо ServerHello + public_key
    private_key, public_pem = generate_rsa_keys()
    server_random = os.urandom(16)
    send_packet(
        conn,
        {
            "step": "server_hello",
            "message": "привіт сервера",
            "server_random": server_random.hex(),
            "public_key": public_pem,
        },
    )
    print("[Крок 2] Надіслано 'привіт сервера', server_random та RSA public key.")
    print(f"         server_random = {server_random.hex()}")

    # Крок 3: Базовий варіант пропускає перевірку CA
    print("[Крок 3] Перевірка сертифіката в CA пропущена (базовий варіант).")

    # Крок 4: Отримуємо та розшифровуємо premaster secret
    premaster_pkt = recv_packet(conn)
    premaster = rsa_decrypt(private_key, premaster_pkt["encrypted_premaster"])
    print(f"[Крок 4] Розшифровано premaster = {premaster.hex()[:32]}... (32 байти)")

    # Крок 5: Генерація спільного сеансового ключа
    session_key = derive_session_key(client_random, server_random, premaster)
    print(f"[Крок 5] Згенеровано session_key = {session_key.hex()}")

    # Крок 6: Обмін зашифрованими повідомленнями "готовий"
    client_ready_pkt = recv_packet(conn)
    client_ready = aes_decrypt(session_key, client_ready_pkt)
    print(f"[Крок 6] Від клієнта отримано розшифроване: '{client_ready}'")
    if client_ready != "готовий":
        raise ValueError("Некоректне підтвердження готовності клієнта!")

    send_packet(conn, aes_encrypt(session_key, "готовий"))
    print("[Крок 6] Надіслано зашифроване 'готовий' клієнту.")

    # Крок 7: Захищений канал передачі даних (чат + прийом файлів)
    print("[Крок 7] Рукостискання завершено! Очікую зашифровані дані...\n")
    while True:
        try:
            enc_pkt = recv_packet(conn)
        except ConnectionError:
            print("[-] Клієнт завершив сеанс.")
            break

        raw_text = aes_decrypt(session_key, enc_pkt)
        data = json.loads(raw_text)

        if data["type"] == "chat":
            msg = data["text"]
            print(f"[Зашифрований пакет] ciphertext={enc_pkt['ciphertext'][:28]}...")
            print(f"[Чат від клієнта]    {msg}")
            reply = f"Сервер отримав ваше повідомлення ({len(msg)} симв.): '{msg}'"
            send_packet(conn, aes_encrypt(session_key, reply))

        elif data["type"] == "file":
            filename = f"received_{os.path.basename(data['filename'])}"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(data["content"])
            print(f"[Файл] Збережено розшифрований файл як '{filename}'")
            reply = f"Файл успішно прийнято та збережено як '{filename}'"
            send_packet(conn, aes_encrypt(session_key, reply))


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"TLS-імітація: сервер запущено на {HOST}:{PORT}")
        conn, addr = srv.accept()
        with conn:
            handle_client(conn, addr)


if __name__ == "__main__":
    main()