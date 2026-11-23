 РГР: Імітація TLS/SSL-рукостискання (базовий варіант)

Реалізація 7 етапів TLS-рукостискання (RSA-2048 + HKDF-SHA256 + AES-256-GCM)
та передачі даних по захищеному каналу (чат і текстові файли) на Python.

## Запуск
```bash
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python server.py   # у першому терміналі
python client.py   # у другому терміналі
```