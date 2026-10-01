# VIBRA v2.1 — persistência online

Esta versão prepara o VIBRA para deixar de depender exclusivamente do `data.json`.

## O que mudou
- Suporte opcional a PostgreSQL através de `DATABASE_URL`.
- Estado da aplicação mantido em memória para preservar as rotas existentes.
- Persistência automática no PostgreSQL após alterações.
- Inicialização cria a tabela `app_state` automaticamente.
- Se `DATABASE_URL` não estiver definida, o VIBRA continua funcionando localmente com `data.json`.
- Versão do health check: 2.1.0.

## Executar localmente
```bash
npm install
npm start
```

Sem `DATABASE_URL`, abre em `http://localhost:3000`.

## Executar com PostgreSQL
Defina:
```bash
export DATABASE_URL="postgresql://UTILIZADOR:SENHA@HOST:5432/vibra"
npm install
npm start
```

Opcionalmente:
```bash
export DATABASE_SSL="false"
```

O servidor cria automaticamente:
`app_state(id, data JSONB, updated_at)`

## Importante
Esta é uma etapa de infraestrutura, não ainda uma configuração final de produção. Antes de receber utilizadores reais, ainda é necessário:
- separar dados em tabelas/entidades para escala;
- armazenamento de fotos e vídeos (object storage);
- HTTPS/reverse proxy;
- segredos fora do código;
- recuperação/verificação de conta;
- backups e monitorização;
- testes de carga e segurança;
- política de privacidade/termos;
- pagamentos com provedor adequado.

## Próximo passo
Construir a camada de mídia e deploy: object storage, upload seguro, compressão/limites, CDN e configuração de produção.


## VIBRA v2.3 — experiência final

Esta versão acrescenta uma camada de experiência do utilizador sobre a infraestrutura v2.2:
- onboarding inicial;
- indicação de estado online/offline;
- instalação como PWA quando suportada pelo navegador;
- alternância de tema;
- melhorias de acessibilidade nos botões principais;
- manutenção das APIs e funcionalidades existentes.

Esta versão continua a precisar de um ambiente de produção real para testes multiutilizador, domínio HTTPS, PostgreSQL gerido, armazenamento de mídia e configuração segura de segredos.


## v2.4
Consulte `V2.4_AUDITORIA_E_CHECKLIST.md` antes do deploy público.
