# Entrega 2 — Hash e autenticação segura

Projeto Integrador · Segurança Aplicada ao Desenvolvimento · UNIT
Solução: **cadastro e login com PBKDF2-HMAC-SHA256 (600.000 iterações)**.

## 1. Problema e objetivo
Uma aplicação precisa cadastrar usuários **sem guardar senhas em texto puro**.
Se o banco vazar, o atacante não deve conseguir ler as senhas nem reaproveitá-las.
Objetivo: criar cadastro/login, guardar só *salt + hash*, testar login correto e
incorreto, explicar por que SHA-256 sozinho não serve e usar a comparação segura
da biblioteca.

## 2. Ambiente e tecnologias
- Python 3.12 (compatível com 3.9+)
- `cryptography` (mesma biblioteca da Entrega 1; nada novo para instalar)
- `sqlite3` e `unittest` (biblioteca padrão)
- Interface: menu no terminal

## 3. Algoritmo, parâmetros e justificativa
| Item | Escolha | Por quê |
|---|---|---|
| Função de hash de senha | PBKDF2-HMAC-SHA256 | Previsto no enunciado e listado no ASVS 11.4.2 |
| Iterações | 600.000 | Mínimo do ASVS 11.4.2 para PBKDF2-SHA256 |
| Salt | 16 bytes aleatórios (`os.urandom`), um por usuário | Mesma senha gera hashes diferentes; barra tabelas pré-computadas |
| Tamanho do hash | 32 bytes | Igual à saída do SHA-256 |
| Comparação | `kdf.verify()` da biblioteca | Tempo constante; não usamos `==` |
| Senha | mínimo 8 caracteres (15 recomendado), máximo 128, sem regra de composição | ASVS 6.2.1 e 6.2.5 |
| Unicode | normalização NFKC antes do hash | "é" sempre vira os mesmos bytes |
| Banco | SQLite com consultas parametrizadas | Evita SQL injection |

**Por que PBKDF2 e não Argon2id?** O Argon2id é ainda mais forte (usa muita memória),
mas exige instalar outra biblioteca. O PBKDF2-SHA256 com 600 mil iterações cumpre o
enunciado e o ASVS, e usa a biblioteca que você já tem. Argon2id fica como melhoria.

## 4. Por que SHA-256 sozinho não serve para senhas
- **É rápido de propósito.** Isso é bom para conferir arquivos e ruim para senhas:
  o atacante testa bilhões de palpites por segundo. Na demo (medida no Windows), SHA-256
  puro faz ~900 mil tentativas/s em um núcleo de CPU; o PBKDF2 com 600 mil iterações
  faz ~11/s (cerca de 80 mil vezes mais lento). Os valores variam conforme o computador.
- **Não tem salt.** Duas pessoas com a mesma senha teriam o mesmo hash, e tabelas
  prontas (*rainbow tables*) quebrariam todas de uma vez.
- *Analogia:* SHA-256 é uma porta giratória (passa rápido). PBKDF2 é um cofre com
  tempo de abertura: para quem tem a senha, 1 espera; para quem chuta milhões, inviável.

## 5. Implementação e execução
```bash
pip install -r requirements.txt

python main.py demo           # cenário completo, sem digitar nada
python main.py                # menu interativo
python test_auth.py           # 18 testes automatizados
```
No menu, a senha **não aparece** enquanto você digita (é de propósito). Para ver,
defina antes `SENHA_VISIVEL=1` (PowerShell: `$env:SENHA_VISIVEL="1"`).

Arquivos: `auth.py` (lógica) · `main.py` (menu e demo) · `test_auth.py` (testes) ·
`evidencias/` (saídas reais) · `usuarios.db` (criado ao usar o menu; fora do Git).

### Fluxo
**Cadastro:** valida usuário e senha → normaliza → gera salt aleatório → deriva o hash
(PBKDF2) → grava `usuario, algoritmo, iteracoes, salt, hash`.
**Login:** busca o usuário → recalcula o hash com o salt guardado → `verify()` compara →
aceita ou recusa. Se o usuário não existir, gasta o mesmo tempo e responde igual.
Se o hash guardado tiver menos iterações que o atual, é atualizado no login.

## 6. Testes e evidências
Saídas em `evidencias/testes.txt` e `evidencias/demo.txt`.
| Cenário | Esperado |
|---|---|
| Cadastro + login com senha correta | Aceito |
| Senha errada / usuário inexistente | Recusado (mesma mensagem) |
| Senha em texto puro no banco | Não aparece |
| Algoritmo, iterações ≥ 600 mil, salt 16 B, hash 32 B | Conferido |
| Mesma senha em dois usuários | Salt e hash diferentes |
| Senha curta, comum, igual ao usuário, longa demais | Recusada |
| Só minúsculas, mas longa | Aceita (sem regra de composição) |
| Unicode composto x decomposto | Mesmo login |
| SQL injection no login | Recusado, tabela intacta |
| Senha de 1 milhão de caracteres | Recusada em menos de 0,5 s |
| Hash antigo (1.000 iterações) | Atualizado no login |

## 7. Riscos, limitações e melhorias
| Limite | Melhoria |
|---|---|
| Sem bloqueio por tentativas (força bruta online) | Limite de tentativas, atraso progressivo, MFA |
| Lista de senhas comuns é pequena e local (ASVS 6.2.12 parcial) | Consultar base de vazadas (ex.: Pwned Passwords) |
| PBKDF2 não usa memória, então GPUs ajudam o atacante | Migrar para Argon2id |
| Mensagem "usuário já existe" no cadastro revela usuários | Cadastro por e-mail com confirmação |
| Banco SQLite sem cifra em repouso | Cifrar disco/banco, controlar permissões |
| Sem recuperação de senha, sessão ou HTTPS (é um terminal) | Fazer em aplicação web com TLS |

## 8. Mapeamento aos padrões
- OWASP Top 10:2025 — **A07** Falhas de autenticação · **A04** Falhas criptográficas
- OWASP ASVS 5.0 — **V6** Autenticação (6.2.1, 6.2.5, 6.2.12 parcial) · **11.4.1** hash aprovado · **11.4.2** KDF lenta
- ISO/IEC 27002:2022 — **5.17** Informação de autenticação · **8.5** Autenticação segura

## 9. Referências
- Documentação oficial da `cryptography` (cryptography.io): PBKDF2HMAC
- RFC 8018 — PKCS #5: Password-Based Cryptography Specification (PBKDF2)
- OWASP Password Storage Cheat Sheet
- OWASP ASVS 5.0; OWASP Top 10:2025; ISO/IEC 27001 e 27002:2022
- Material da aula (Profa. Ana Carla do Nascimento Santos)
