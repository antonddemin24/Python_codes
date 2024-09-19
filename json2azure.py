import requests
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from azure.storage.blob import BlobServiceClient

# Функция для проверки первых 10 байтов HMAC-SHA256
def verify_hmac10(ciphertext, hmac_key, iv, expected_hmac10):
    computed_hmac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    return computed_hmac[:10] == expected_hmac10

def download_and_decrypt(json_data):
    # Получаем необходимые данные из JSON
    file_name = json_data['file_name']
    media_url = json_data['cdn_url']
    encryption_metadata = json_data['encryption_metadata']
    encryption_key = base64.b64decode(encryption_metadata['encryption_key'])
    hmac_key = base64.b64decode(encryption_metadata['hmac_key'])
    iv = base64.b64decode(encryption_metadata['iv'])
    plaintext_hash = base64.b64decode(encryption_metadata['plaintext_hash'])
    enc_hash = base64.b64decode(encryption_metadata['encrypted_hash'])

    # Скачиваем файл из CDN
    response = requests.get(media_url)
    if response.status_code != 200:
        raise Exception(f"Ошибка при скачивании файла: {response.status_code}")
    
    cdn_file = response.content
    ciphertext = cdn_file[:-10]  # Зашифрованные данные (без последних 10 байт)
    hmac10 = cdn_file[-10:]  # Последние 10 байт для HMAC-SHA256

    # Проверка SHA-256 хэша зашифрованного файла
    calculated_enc_hash = hashlib.sha256(cdn_file).digest()
    if calculated_enc_hash != enc_hash:
        raise ValueError("SHA-256 хэш зашифрованного файла не совпадает с enc_hash. Данные повреждены.")

    # Проверка первых 10 байтов HMAC-SHA256
    if not verify_hmac10(ciphertext, hmac_key, iv, hmac10):
        raise ValueError("Первые 10 байтов HMAC-SHA256 не совпадают. Данные повреждены.")

    # Расшифровка файла с использованием AES-CBC
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_file = decryptor.update(ciphertext) + decryptor.finalize()

    # Удаление паддинга (PKCS7)
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_file = unpadder.update(decrypted_padded_file) + unpadder.finalize()

    # Проверка SHA-256 хэша расшифрованного файла
    calculated_plaintext_hash = hashlib.sha256(decrypted_file).digest()
    if calculated_plaintext_hash != plaintext_hash:
        raise ValueError("SHA-256 хэш расшифрованного файла не совпадает с plaintext_hash. Данные повреждены.")
    
    # Загрузка расшифрованного файла в Azure Blob Storage
    blob_service_client = BlobServiceClient.from_connection_string("<AZURE_STORAGE_CONNECTION_STRING>")
    container_name = "your-container-name"
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=file_name)

    blob_client.upload_blob(decrypted_file, overwrite=True)

    # Ссылка на расшифрованный файла
    blob_url = blob_client.url
    # return blob_url

    # Возвращаем результат
    return decrypted_file

# Пример использования функции
json_data = {
    'file_name': '\u200ephoto.jpg',
    'media_id': '94576B50-960A-4E57-9FCD-1FAFD9162604',
    'cdn_url': 'https://mmg.whatsapp.net/v/t62.66612-24/13202977_8174428009259817_529646540402282076_n.enc?ccb=11-4&oh=01_Q5AaILsZ0SOTiNuMMWfkt85F0hiQA7n4GS4iUI1mmzcDo0xh&oe=6713EEFD&_nc_sid=5e03e0&mms3=true',
    'encryption_metadata': {
        'encryption_key': 'LrJUiWoyfzH+7tEeehisggexlzXOto0OCqwdXu1ag0g=',
        'hmac_key': '6dFSGplwstBKlyHTOUgCKY3TZ3U30oW5vfGoQDPUTaA=',
        'hmac': 'S+/20RWdlZ+qBZVZ8piCMc0gh0obv7g0l0A6n4XuE2k=',
        'iv': 'j2e4oogtFbtg8GpGNixDEA==',
        'plaintext_hash': 'vUOg8nP97L+sdT1ZGNoy83kCGOfNpkgKryQ4V2E8Yco=',
        'encrypted_hash': 'WU2giWcd9hxeFfBiZ/69BDYPARfqL+r7NC1YkoiMO5A='
    }
}

try:
    decrypted_file = download_and_decrypt(json_data)
    print("Файл успешно расшифрован и проверен.")
    # Вы можете сохранить расшифрованный файл
    with open('decrypted_file.jpg', 'wb') as f:
        f.write(decrypted_file)
except Exception as e:
    print(f"An error occurred: {e}")