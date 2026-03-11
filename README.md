# Community API

Backend responsável pela autenticação segura, gestão de credenciais, comunicação criptografada e serviços principais do sistema de serviços comunitários.

Este projeto foi desenvolvido como parte do **Projeto Integrador de Políticas de Segurança da Informação**, cujo objetivo é implementar um sistema com mecanismos robustos de autenticação, proteção de dados e conformidade com a LGPD.

---

# Arquitetura

A API foi construída utilizando **ASP.NET Core** seguindo princípios de arquitetura em camadas.

src/

* Api → Controllers e endpoints HTTP
* Application → Regras de negócio
* Domain → Entidades e modelos do domínio
* Infrastructure → Persistência, criptografia e serviços externos

tests/

* Testes unitários
* Testes de segurança

docs/

* Documentação técnica
* Diagramas de arquitetura
* Fluxos de autenticação

---

# Tecnologias Utilizadas

* .NET / ASP.NET Core
* Entity Framework Core
* PostgreSQL
* JWT Authentication
* BCrypt / Argon2 para hashing de senhas
* AES para criptografia de dados sensíveis
* TLS/HTTPS para comunicação segura

---

# Funcionalidades de Segurança

## Autenticação Segura

O sistema implementa autenticação baseada em credenciais com:

* Hash criptográfico seguro (Argon2 ou BCrypt)
* Salt único por usuário
* Política de sessão com expiração
* Proteção contra ataques de força bruta

## Autenticação de Dois Fatores (2FA)

Fluxo:

1. Usuário envia credenciais
2. Sistema valida hash da senha
3. Sistema solicita código 2FA
4. Código temporário é validado
5. Sessão autenticada é criada

Possíveis métodos:

* TOTP (Google Authenticator)
* Email OTP

---

# Recuperação de Senha

O sistema implementa um fluxo seguro de recuperação de senha baseado em token.

Processo:

1. Usuário solicita recuperação
2. Sistema gera token criptograficamente seguro
3. Token possui tempo de expiração
4. Token é invalidado após uso
5. Novo hash de senha é gerado

Logs são registrados para auditoria.

---

# Criptografia

## Dados em trânsito

Toda comunicação é protegida por:

HTTPS / TLS 1.2+

Conexões HTTP são bloqueadas.

## Dados em repouso

Informações sensíveis são criptografadas utilizando:

AES-256

Exemplos:

* tokens
* dados pessoais sensíveis

---

# Auditoria e Logs

Eventos críticos são registrados:

* autenticação
* falhas de login
* uso de 2FA
* recuperação de senha
* alteração de dados sensíveis

Os logs são protegidos contra alteração.

---

# Conformidade com LGPD

O sistema implementa princípios fundamentais da LGPD:

* minimização de dados
* finalidade clara do tratamento
* consentimento explícito
* possibilidade de revogação

Direitos do titular implementados:

* consulta de dados
* exportação
* exclusão de dados pessoais

---

# Executando o Projeto

Requisitos:

* .NET SDK
* PostgreSQL

Instalação:

dotnet restore

Execução:

dotnet run

---

# Testes

dotnet test

Os testes incluem:

* validação de autenticação
* fluxo de recuperação de senha
* validação de criptografia
* testes de segurança

---

# Documentação

Documentação completa disponível em:

/docs

Inclui:

* arquitetura do sistema
* fluxos de autenticação
* análise de riscos
* testes de segurança

---

# Licença

Uso acadêmico.
