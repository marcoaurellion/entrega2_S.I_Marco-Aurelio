"""Linha de comando da Entrega 2 (cadastro e login com PBKDF2-HMAC-SHA256).

Uso:
  python main.py          abre o menu interativo
  python main.py demo     roda um cenário completo, sem digitar nada

Dica: a senha não aparece enquanto você digita (é de propósito). Para ver o
que digita, defina antes a variável SENHA_VISIVEL=1.
"""
import getpass
import hashlib
import os
import sys
import time

import auth

ARQUIVO_BANCO = "usuarios.db"


def ler_senha(texto):
    if os.environ.get("SENHA_VISIVEL") == "1":
        return input(texto)
    return getpass.getpass(texto + "(não aparece ao digitar) ")


def mostrar_registros(con):
    linhas = auth.listar_registros(con)
    if not linhas:
        print("  (nenhum usuário cadastrado)")
    for r in linhas:
        print(f"  usuário:   {r['usuario']}")
        print(f"  algoritmo: {r['algoritmo']} | iterações: {r['iteracoes']}")
        print(f"  salt:      {r['salt']}")
        print(f"  hash:      {r['senha_hash']}")
        print()


def menu():
    con = auth.conectar(ARQUIVO_BANCO)
    while True:
        print("\n=== Cadastro e Login ===")
        print("1) Cadastrar   2) Entrar   3) Ver como as senhas ficam guardadas   0) Sair")
        op = input("Escolha: ").strip()
        if op == "1":
            usuario = input("Novo usuário: ")
            senha = ler_senha("Senha: ")
            try:
                auth.cadastrar(con, usuario, senha)
                print("Cadastro realizado.")
            except ValueError as e:
                print(f"Não foi possível cadastrar: {e}")
        elif op == "2":
            usuario = input("Usuário: ")
            senha = ler_senha("Senha: ")
            if auth.autenticar(con, usuario, senha):
                print("LOGIN ACEITO")
            else:
                print("LOGIN RECUSADO: usuário ou senha inválidos")
        elif op == "3":
            mostrar_registros(con)
        elif op == "0":
            break
        else:
            print("Opção inválida.")
    con.close()


def demo():
    con = auth.conectar(":memory:")
    senha_ana = "cafe com leite no fim da tarde"   # senha fictícia de demonstração

    print("1) Cadastro de 'ana' (a senha NÃO é guardada; só salt + hash)")
    auth.cadastrar(con, "ana", senha_ana)
    mostrar_registros(con)
    guardou_texto = any(senha_ana in str(tuple(r)) for r in auth.listar_registros(con))
    print(f"   Senha em texto puro no banco? {'SIM' if guardou_texto else 'NÃO'}")

    print("\n2) Outro usuário com a MESMA senha (o salt muda, então o hash muda)")
    auth.cadastrar(con, "bruno", senha_ana)
    a, b = auth.listar_registros(con)
    print(f"   mesmo salt?  {'SIM' if a['salt'] == b['salt'] else 'NÃO'}")
    print(f"   mesmo hash?  {'SIM' if a['senha_hash'] == b['senha_hash'] else 'NÃO'}")

    print("\n3) Login com a senha correta")
    print("   ana  ->", "ACEITO" if auth.autenticar(con, "ana", senha_ana) else "RECUSADO")

    print("\n4) Login com senha errada")
    print("   ana  ->", "ACEITO" if auth.autenticar(con, "ana", "senha errada!") else "RECUSADO")

    print("\n5) Login com usuário que não existe (mesma resposta, sem pistas)")
    print("   zeca ->", "ACEITO" if auth.autenticar(con, "zeca", senha_ana) else "RECUSADO")

    print("\n6) Cadastro com senhas fracas")
    for fraca in ("abc123", "12345678"):
        try:
            auth.cadastrar(con, "carla", fraca)
        except ValueError as e:
            print(f"   '{fraca}' -> recusada: {e}")

    print("\n7) Por que SHA-256 sozinho não serve para senhas")
    n = 200_000
    t0 = time.perf_counter()
    for i in range(n):
        hashlib.sha256(b"senha%d" % i).digest()
    t_sha = time.perf_counter() - t0
    t0 = time.perf_counter()
    auth.gerar_hash("senha de teste")
    t_kdf = time.perf_counter() - t0
    print(f"   SHA-256 puro:  ~{n / t_sha:,.0f} tentativas por segundo")
    print(f"   PBKDF2 600 mil iterações: ~{1 / t_kdf:,.1f} tentativas por segundo")
    print(f"   O atacante fica ~{(n / t_sha) / (1 / t_kdf):,.0f} vezes mais lento.")
    con.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
    else:
        menu()
