import base64
import requests
from azure.storage.blob import BlobServiceClient

def get_blob_as_base64(blob_url, connection_string):
    # Создаем объект клиента BlobServiceClient
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)

    # Извлекаем имя контейнера и имя блоба из URL
    parts = blob_url.split('/')
    storage_account_name = parts[2].split('.')[0]
    container_name = parts[3]
    blob_name = '/'.join(parts[4:])

    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

    # Загружаем содержимое блоба
    try:
        blob_data = blob_client.download_blob().readall()
    except Exception as e:
        raise Exception(f"Ошибка при загрузке блоба: {e}")

    # Преобразуем содержимое в Base64
    base64_image = base64.b64encode(blob_data).decode('utf-8')

    return base64_image

# Пример использования
blob_url = 'https://my-storage-account.blob.core.windows.net/my-container/decrypted_file.jpg'
connection_string = '<AZURE_STORAGE_CONNECTION_STRING>'

try:
    base64_image = get_blob_as_base64(blob_url, connection_string)
    print(f"Base64 Image: {base64_image}")
except Exception as e:
    print(f"An error occurred: {e}")