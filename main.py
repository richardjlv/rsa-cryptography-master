from aes import AES
from rsa import RSA
from file import FileHandler

aes = AES()
rsa = RSA("arquivo.txt")
file_handler = FileHandler("arquivo.txt")

menu_options = {
    1: 'Cifração de uma mensagem com AES',
    2: 'Cifra híbrida',
    3: 'Cifra híbrida (autenticação mútua)',
    4: 'Geração de Assinatura de A',
    5: 'Verificação da assinatura',
    6: 'Cifração, decifração e assinatura de um documento',
    7: 'Sair' 
}

def print_menu():
    for key in menu_options.keys():
        print (key, '--', menu_options[key] )

def case_1():
    plaintext = input('Digite uma mensagem: ')
    password = input('Digite uma senha: ')

    ciphertext = aes.encrypt(plaintext, password)
    print(f"[AES] Mensagem cifrada: {ciphertext}")
    message = aes.decrypt(ciphertext, password)
    print(f"[AES] Mensagem decifrada: {message}")
    return

def case_2():
    plaintext = input('Digite uma mensagem: ')
    password = input('Digite uma senha: ')
    cipher_aes = aes.encrypt(plaintext, password)
    print(f"[AES] Mensagem cifrada: {cipher_aes}")

    e, n, d = rsa.generate_key_pair()
    cipher_rsa = rsa.encrypt(cipher_aes, e, n)
    print(f"[RSA] Mensagem cifrada: {cipher_rsa}")
    cipher_aes = rsa.decrypt(cipher_rsa, d, n).encode()
    print(f"[RSA] Mensagem decifrada: {cipher_aes}")

    original_message = aes.decrypt(cipher_aes, password)
    print(f"[AES] Mensagem decifrada: {original_message}")

    return
    
def case_3():
    plaintext = input('Digite uma mensagem: ')
    password = input('Digite uma senha: ')
    cipher_aes = aes.encrypt(plaintext, password)
    print(f"[AES] Mensagem cifrada: {cipher_aes}")

    e_a, n_a, d_a = rsa.generate_key_pair()
    e_b, n_b, d_b = rsa.generate_key_pair()

    cipher_rsa_b_to_a = rsa.encrypt(cipher_aes, e_a, n_a)
    print(f"[RSA] Mensagem cifrada B para A: {cipher_rsa_b_to_a}")

    cipher_rsa_a_to_b = rsa.encrypt(cipher_aes, e_b, n_b)
    print(f"[RSA] Mensagem cifrada A para B: {cipher_rsa_a_to_b}")

    decipher_a_to_b = rsa.decrypt(cipher_rsa_a_to_b.encode(), d_b, n_b)
    print(f"[RSA] Mensagem decifrada de A para B: {decipher_a_to_b}")

    decipher_b_to_a = rsa.decrypt(cipher_rsa_b_to_a.encode(), d_a, n_a)
    print(f"[RSA] Mensagem decifrada de B para A: {decipher_b_to_a}")

    original_message = aes.decrypt(decipher_b_to_a.encode(), password)
    print(f"[AES] Mensagem decifrada: {original_message}")

    return

def case_4():
    plaintext = input('Digite uma mensagem: ')
    password = input('Digite uma senha: ')
    cipher_aes = aes.encrypt(plaintext, password)
    print(f"[AES] Mensagem cifrada: {cipher_aes}")

    e, n, d = rsa.generate_key_pair()
    cipher_rsa = rsa.encrypt(cipher_aes, e, n)
    print(f"[RSA] Mensagem cifrada: {cipher_rsa}")

    sign_rsa = rsa.sign_message(cipher_aes, d, n)
    print(f"[RSA] Assinatura da mensagem: {sign_rsa}")

    return

def case_5():
    plaintext = input('Digite uma mensagem: ')
    password = input('Digite uma senha: ')
    cipher_aes = aes.encrypt(plaintext, password)
    print(f"[AES] Mensagem cifrada: {cipher_aes}")

    e, n, d = rsa.generate_key_pair()
    cipher_rsa = rsa.encrypt(cipher_aes, e, n)
    print(f"[RSA] Mensagem cifrada: {cipher_rsa}")

    cipher_aes = rsa.decrypt(cipher_rsa, d, n).encode()
    print(f"[RSA] Mensagem decifrada: {cipher_aes}")

    original_message = aes.decrypt(cipher_aes, password)
    print(f"[AES] Mensagem decifrada: {original_message}")

    sign_rsa = rsa.sign_message(cipher_aes, d, n)
    print(f"[RSA] Assinatura da mensagem: {sign_rsa}")

    is_valid = rsa.check_signature(cipher_aes, sign_rsa, e, n)
    print(f"[RSA] Verificação da assinatura: {is_valid}")
    
    return

def case_6():
    message = file_handler.read()

    e, n, d = rsa.generate_key_pair()
    cipher_rsa = rsa.encrypt(message, e, n)
    print(f"[RSA] Mensagem cifrada: {cipher_rsa}")

    mensagem_original = rsa.decrypt(cipher_rsa, d, n)
    print(f"[RSA] Mensagem decifrada: {mensagem_original}")

    sign_rsa = rsa.sign_message(cipher_rsa.encode(), d, n)
    print(f"[RSA] Assinatura da mensagem: {sign_rsa}")

    is_valid = rsa.check_signature(cipher_rsa.encode(), sign_rsa, e, n)
    print(f"[RSA] Verificação da assinatura: {is_valid}")

while(True):
    print_menu()
    option = ''
    try:
        option = int(input('Escolhe uma opção: '))
    except:
        print('Por favor, digite um número.')
    if option == 1:
        case_1()
    elif option == 2:
        case_2()
    elif option == 3:
        case_3()
    elif option == 4:
        case_4()
    elif option == 5:
        case_5()
    elif option == 6:
        case_6()
    elif option == 7:
        exit()
    else:
        print('Opção inválida, por favor escolha um número entre 1 e 5.')