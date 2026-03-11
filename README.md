# Integrity Monitor

O Integrity Monitor é uma solução de segurança desenvolvida para monitorizar a integridade de ficheiros em sistemas Windows. Este projeto foca-se em auto-proteção e na distinção inteligente entre atualizações legítimas e modificações maliciosas.

## Diferenciais Técnicos & Segurança

Este projeto demonstra competências em Cibersegurança e Programação de Sistemas:

* **Proteção de Baseline com HMAC-SHA256:** A base de dados de integridade (ficheiro JSON) é assinada digitalmente com uma chave baseada em password. Isso garante que um atacante não consiga modificar a baseline para ocultar malware.
* **Gestão Dinâmica de ACLs (Windows):** Utiliza o utilitário `icacls` para restringir permissões. O software "destranca" os ficheiros de log e baseline apenas durante a escrita, mantendo-os em modo *Read-Only* no restante tempo.
* **Verificação de Assinaturas Digitais:** Integração com APIs do Windows para validar se binários alterados possuem assinaturas digitais válidas, reduzindo falsos positivos em atualizações de sistema.
* **Sistema de Log Rotativo Protegido:** Implementação de logs que respeitam limites de tamanho e quantidade, com as mesmas proteções de acesso aplicadas aos ficheiros críticos.

## Como Funciona

O monitor foca-se em diretórios sensíveis como `C:\Windows\System32` e monitoriza extensões críticas: `.exe`, `.dll`, `.sys`, `.ps1`, `.bat`, `.cmd`.

### Lógica de Verificação
A integridade é validada através da comparação de múltiplos vetores:

1.  **Metadados:** Tamanho do ficheiro e data de modificação (`mtime`).
2.  **Hashing:** Cálculo de $SHA-256$ para detetar alterações de bits.
3.  **Assinatura:** Caso o hash mude, o sistema verifica se o ficheiro está assinado digitalmente.

## Como Utilizar

**Aviso:** Este script requer privilégios de **Administrador** para manipular permissões de ficheiros em `C:\ProgramData`.

### 1. **Instalação**
Clone o repositório e instala as dependências (se aplicável):

```bash
git clone [https://github.com/teu-utilizador/advanced-integrity-monitor.git](https://github.com/teu-utilizador/advanced-integrity-monitor.git)
cd advanced-integrity-monitor
```

### 2. Criar a Baseline Inicial
Dentro da aplicação, clique em **"Criar Baseline"** para definir o estado "seguro" do sistema e defina a sua password de proteção.

### 3. Verificar Integridade
Clique em **"Verificar Integridade"**. O sistema irá comparar o estado atual com a baseline protegida por HMAC.

---

## Classificação de Alertas

* 🔴 **SECURITY:** Ficheiros novos, modificações sem assinatura ou violação das ACLs da pasta segura.
* 🟡 **WARNING:** Ficheiros em falta ou atualizações de sistema com assinatura válida.
* ⚪ **ERROR:** Falhas de acesso ou erros de leitura de ficheiros.

---

## Hardening e Boas Práticas

* **Isolamento:** Todos os dados sensíveis são guardados em `C:\ProgramData\IntegrityMonitor`.
* **Exclusões Inteligentes:** O monitor ignora automaticamente pastas de logs temporários e ficheiros `.tmp` para evitar ruído e overhead de processamento.
* **Integridade da Baseline:** O uso de `hmac.compare_digest` previne ataques de temporização (*timing attacks*).


