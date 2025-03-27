import random

def gerador_de_senhas(tamanho):
    caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    senha = ""

    if tamanho <= 8:
        raise ValueError("O tamanho da senha deve ser maior que 8.")
    elif tamanho > 128:
        raise ValueError("O tamanho da senha deve ser menor ou igual a 128.")


    for i in range(tamanho):
        senha += caracteres[random.randint(0, len(caracteres) - 1)]
    return senha

def main():
    tamanho = int(input("Digite o tamanho da senha: "))
    senha = gerador_de_senhas(tamanho)
    print(f"A senha gerada é: {senha}")

if __name__ == "__main__":
    main()