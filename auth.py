"""Entrega 2 - Cadastro e login com hash seguro de senhas.

Algoritmo: PBKDF2-HMAC-SHA256 com 600.000 iterações (biblioteca `cryptography`).
A comparação é feita pela própria biblioteca (`verify`), em tempo constante.
Nenhum algoritmo criptográfico é implementado manualmente.
"""
import base64
import os
import re
import sqlite3
import unicodedata

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ALGORITMO = "pbkdf2_sha256"
ITERACOES = 600_000      # ASVS 5.0, requisito 11.4.2 (PBKDF2-SHA256 >= 600 mil)
TAM_SALT = 16            # 128 bits, aleatório por usuário
TAM_HASH = 32            # 256 bits
SENHA_MIN = 8            # ASVS 6.2.1 (mínimo 8; 15 é recomendado)
SENHA_MAX = 128          # limite para evitar abuso de CPU com senhas gigantes

# Lista pequena e LOCAL de senhas muito comuns (ASVS 6.2.12, atendimento parcial).
SENHAS_COMUNS = {
    "12345678", "123456789", "1234567890", "12345678910", "11111111",
    "00000000", "123123123", "password", "password1", "password123",
    "qwerty123", "qwertyuiop", "1q2w3e4r", "abc12345", "admin123",
    "iloveyou", "senha123", "senha1234", "minhasenha", "brasil123",
    "mudar123", "teste123", "flamengo", "corinthians",
}

_PADRAO_USUARIO = re.compile(r"^[a-z0-9_.-]{3,30}$")
_SALT_FALSO = b"\x00" * TAM_SALT   # usado quando o usuário não existe


# ---------------------------------------------------------------- banco ----
def conectar(caminho="usuarios.db"):
    con = sqlite3.connect(caminho)
    con.row_factory = sqlite3.Row
    con.execute(
        """CREATE TABLE IF NOT EXISTS usuarios (
               id         INTEGER PRIMARY KEY AUTOINCREMENT,
               usuario    TEXT NOT NULL UNIQUE,
               algoritmo  TEXT NOT NULL,
               iteracoes  INTEGER NOT NULL,
               salt       TEXT NOT NULL,
               senha_hash TEXT NOT NULL,
               criado_em  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
           )"""
    )
    con.commit()
    return con


# ---------------------------------------------------------------- hash -----
def _normalizar(senha):
    """Normaliza o Unicode (NFKC) para que 'é' tenha sempre os mesmos bytes."""
    return unicodedata.normalize("NFKC", senha)


def _kdf(salt, iteracoes):
    # Um objeto PBKDF2HMAC só pode ser usado uma vez; por isso criamos um novo.
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=TAM_HASH,
                      salt=salt, iterations=iteracoes)


def gerar_hash(senha, iteracoes=ITERACOES):
    """Devolve (salt, hash) em bytes. O salt é novo e aleatório a cada chamada."""
    salt = os.urandom(TAM_SALT)
    derivado = _kdf(salt, iteracoes).derive(_normalizar(senha).encode("utf-8"))
    return salt, derivado


# ---------------------------------------------------------- validações -----
def validar_usuario(usuario):
    usuario = usuario.strip().lower()
    if not _PADRAO_USUARIO.match(usuario):
        raise ValueError("Usuário inválido: use 3 a 30 letras minúsculas, "
                         "números, ponto, hífen ou sublinhado.")
    return usuario


def validar_senha(senha, usuario=""):
    s = _normalizar(senha)
    if len(s) < SENHA_MIN:
        raise ValueError(f"Senha muito curta: mínimo de {SENHA_MIN} caracteres "
                         "(recomendado: 15 ou mais).")
    if len(s) > SENHA_MAX:
        raise ValueError(f"Senha muito longa: máximo de {SENHA_MAX} caracteres.")
    if s.lower() in SENHAS_COMUNS:
        raise ValueError("Senha muito comum. Escolha outra.")
    if usuario and s.lower() == usuario.lower():
        raise ValueError("A senha não pode ser igual ao usuário.")
    # De propósito NÃO exigimos maiúscula, número ou símbolo (ASVS 6.2.5).


# ------------------------------------------------------ cadastro e login ---
def cadastrar(con, usuario, senha):
    usuario = validar_usuario(usuario)
    validar_senha(senha, usuario)
    salt, derivado = gerar_hash(senha)
    try:
        con.execute(
            "INSERT INTO usuarios (usuario, algoritmo, iteracoes, salt, senha_hash) "
            "VALUES (?, ?, ?, ?, ?)",           # consulta parametrizada (sem SQL injection)
            (usuario, ALGORITMO, ITERACOES,
             base64.b64encode(salt).decode("ascii"),
             base64.b64encode(derivado).decode("ascii")),
        )
        con.commit()
    except sqlite3.IntegrityError:
        raise ValueError("Esse usuário já existe.")


def autenticar(con, usuario, senha):
    """True se usuário e senha conferem; False em qualquer outro caso."""
    usuario = usuario.strip().lower()
    if len(senha) > SENHA_MAX:      # não gasta CPU com entrada absurda
        return False
    senha_bytes = _normalizar(senha).encode("utf-8")

    linha = con.execute(
        "SELECT id, iteracoes, salt, senha_hash FROM usuarios WHERE usuario = ?",
        (usuario,),
    ).fetchone()

    if linha is None:
        # Gasta o mesmo tempo, para não revelar se o usuário existe.
        _kdf(_SALT_FALSO, ITERACOES).derive(senha_bytes)
        return False

    salt = base64.b64decode(linha["salt"])
    esperado = base64.b64decode(linha["senha_hash"])
    try:
        # A comparação em tempo constante é feita pela biblioteca.
        _kdf(salt, linha["iteracoes"]).verify(senha_bytes, esperado)
    except InvalidKey:
        return False

    if linha["iteracoes"] < ITERACOES:   # hash antigo e mais fraco: atualiza
        novo_salt, novo_hash = gerar_hash(senha)
        con.execute(
            "UPDATE usuarios SET algoritmo=?, iteracoes=?, salt=?, senha_hash=? "
            "WHERE id=?",
            (ALGORITMO, ITERACOES,
             base64.b64encode(novo_salt).decode("ascii"),
             base64.b64encode(novo_hash).decode("ascii"), linha["id"]),
        )
        con.commit()
    return True


def listar_registros(con):
    """Devolve como os usuários estão guardados (para mostrar como evidência)."""
    return con.execute(
        "SELECT usuario, algoritmo, iteracoes, salt, senha_hash FROM usuarios "
        "ORDER BY id"
    ).fetchall()
