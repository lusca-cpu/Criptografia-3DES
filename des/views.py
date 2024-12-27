from django.core.files.base import ContentFile
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.core.files.storage import FileSystemStorage
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import os
import base64

# Função auxiliar para obter a chave Triple DES
def get_triple_des_key(keys):
    combined_key = ''.join(keys)
    while len(combined_key) < 24:
        combined_key += combined_key
    return combined_key[:24].encode('utf-8')

# Página inicial
def index(request):
    return render(request, 'index.html')

# Página de encriptação
def encrypt(request):
    if request.method == 'POST' and request.FILES['file']:
        # Receber o arquivo
        uploaded_file = request.FILES['file']
        fs = FileSystemStorage()
        file_path = fs.save(uploaded_file.name, uploaded_file)
        file_path = fs.path(file_path)

        # Receber as chaves de encriptação
        key1 = request.POST.get('key1')
        key2 = request.POST.get('key2')
        key3 = request.POST.get('key3')

        # Gerar a chave Triple DES
        secret_key = get_triple_des_key([key1, key2, key3])

        # Ler o conteúdo do arquivo
        with open(file_path, 'rb') as file:
            plain_data = file.read()

        # Encriptar o arquivo usando Triple DES
        cipher = DES3.new(secret_key, DES3.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(plain_data, DES3.block_size))

        # Converter para Base64 para facilitar o armazenamento
        encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')

        # Enviar o arquivo encriptado de volta para o usuário
        response = HttpResponse(encrypted_base64, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="encrypted_image.txt"'
        return response

    return render(request, 'encrypt.html')

# Página de decriptação
def decrypt(request):
    if request.method == 'POST' and request.FILES['file']:
        # Receber o arquivo encriptado
        uploaded_file = request.FILES['file']
        encrypted_data = uploaded_file.read()

        # Receber as chaves de decriptação
        key1 = request.POST.get('key1')
        key2 = request.POST.get('key2')
        key3 = request.POST.get('key3')

        # Gerar a chave Triple DES
        secret_key = get_triple_des_key([key1, key2, key3])

        # Converter o arquivo encriptado de Base64 para binário
        encrypted_data = base64.b64decode(encrypted_data)

        # Desencriptar o arquivo
        try:
            cipher = DES3.new(secret_key, DES3.MODE_ECB)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), DES3.block_size)
        except (ValueError, KeyError) as e:
            return JsonResponse({"error": "Chave incorreta ou arquivo corrompido"}, status=400)
            
        # Enviar o arquivo desencriptado de volta para o usuário
        response = HttpResponse(decrypted_data, content_type='image/jpeg')
        response['Content-Disposition'] = 'attachment; filename="decrypted_image.jpg"'
        
        # Certificar-se de que apenas uma resposta é retornada
        return response

    return render(request, 'decrypt.html')
