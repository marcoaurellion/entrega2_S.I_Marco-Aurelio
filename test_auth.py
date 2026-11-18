import base64
import time
import unicodedata
import unittest

import auth

SENHA = "cafe com leite no fim da tarde"


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.con = auth.conectar(":memory:")
        self.addCleanup(self.con.close)

    def _registro(self, usuario):
        return self.con.execute(
            "SELECT * FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()

    # --- fluxo principal ---
    def test_cadastro_e_login_corretos(self):
        auth.cadastrar(self.con, "ana", SENHA)
        self.assertTrue(auth.autenticar(self.con, "ana", SENHA))

    def test_login_com_senha_errada(self):
        auth.cadastrar(self.con, "ana", SENHA)
        self.assertFalse(auth.autenticar(self.con, "ana", "senha errada!"))

    def test_login_com_usuario_inexistente(self):
        self.assertFalse(auth.autenticar(self.con, "zeca", SENHA))

    def test_usuario_nao_diferencia_maiuscula(self):
        auth.cadastrar(self.con, "Ana", SENHA)
        self.assertTrue(auth.autenticar(self.con, "ANA", SENHA))

    # --- armazenamento protegido ---
    def test_senha_nao_fica_em_texto_puro(self):
        auth.cadastrar(self.con, "ana", SENHA)
        self.assertNotIn(SENHA, str(tuple(self._registro("ana"))))

    def test_algoritmo_iteracoes_salt_e_hash(self):
        auth.cadastrar(self.con, "ana", SENHA)
        r = self._registro("ana")
        self.assertEqual(r["algoritmo"], "pbkdf2_sha256")
        self.assertGreaterEqual(r["iteracoes"], 600_000)
        self.assertEqual(len(base64.b64decode(r["salt"])), 16)
        self.assertEqual(len(base64.b64decode(r["senha_hash"])), 32)

    def test_salt_unico_por_usuario(self):
        auth.cadastrar(self.con, "ana", SENHA)
        auth.cadastrar(self.con, "bruno", SENHA)
        a, b = self._registro("ana"), self._registro("bruno")
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertNotEqual(a["senha_hash"], b["senha_hash"])

    # --- regras de senha e de usuário ---
    def test_usuario_duplicado_recusado(self):
        auth.cadastrar(self.con, "ana", SENHA)
        with self.assertRaises(ValueError):
            auth.cadastrar(self.con, "ana", SENHA)

    def test_senha_curta_recusada(self):
        with self.assertRaises(ValueError):
            auth.cadastrar(self.con, "ana", "abc123")

    def test_senha_comum_recusada(self):
        with self.assertRaises(ValueError):
            auth.cadastrar(self.con, "ana", "12345678")

    def test_senha_igual_ao_usuario_recusada(self):
        with self.assertRaises(ValueError):
            auth.cadastrar(self.con, "usuario123", "usuario123")

    def test_senha_muito_longa_recusada(self):
        with self.assertRaises(ValueError):
            auth.cadastrar(self.con, "ana", "a" * 129)

    def test_sem_regra_de_composicao(self):
        # ASVS 6.2.5: só letras minúsculas, mas longa, deve ser aceita
        auth.cadastrar(self.con, "ana", "apenasletrasminusculaslongas")
        self.assertTrue(auth.autenticar(self.con, "ana", "apenasletrasminusculaslongas"))

    def test_usuario_invalido_recusado(self):
        for ruim in ("a", "com espaco", "ana'; DROP TABLE usuarios;--", "x" * 31):
            with self.assertRaises(ValueError):
                auth.cadastrar(self.con, ruim, SENHA)

    # --- robustez e ataques ---
    def test_normalizacao_unicode(self):
        senha_nfc = unicodedata.normalize("NFC", "açaí com café especial")
        senha_nfd = unicodedata.normalize("NFD", senha_nfc)
        self.assertNotEqual(senha_nfc, senha_nfd)
        auth.cadastrar(self.con, "ana", senha_nfc)
        self.assertTrue(auth.autenticar(self.con, "ana", senha_nfd))

    def test_sql_injection_no_login(self):
        auth.cadastrar(self.con, "ana", SENHA)
        self.assertFalse(auth.autenticar(self.con, "ana' OR '1'='1", SENHA))
        self.assertFalse(auth.autenticar(self.con, "' OR 1=1 --", "qualquer coisa"))
        total = self.con.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
        self.assertEqual(total, 1)

    def test_senha_enorme_nao_trava(self):
        auth.cadastrar(self.con, "ana", SENHA)
        t0 = time.perf_counter()
        self.assertFalse(auth.autenticar(self.con, "ana", "a" * 1_000_000))
        self.assertLess(time.perf_counter() - t0, 0.5)

    def test_hash_antigo_e_atualizado_no_login(self):
        salt, derivado = auth.gerar_hash(SENHA, iteracoes=1000)
        self.con.execute(
            "INSERT INTO usuarios (usuario, algoritmo, iteracoes, salt, senha_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            ("velho", "pbkdf2_sha256", 1000,
             base64.b64encode(salt).decode(), base64.b64encode(derivado).decode()))
        self.con.commit()
        self.assertTrue(auth.autenticar(self.con, "velho", SENHA))
        self.assertEqual(self._registro("velho")["iteracoes"], auth.ITERACOES)
        self.assertTrue(auth.autenticar(self.con, "velho", SENHA))


if __name__ == "__main__":
    unittest.main(verbosity=2)
