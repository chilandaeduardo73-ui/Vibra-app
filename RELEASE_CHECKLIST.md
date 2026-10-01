# VIBRA 2.2 — Release Candidate

## Incluído
- PostgreSQL opcional com persistência JSONB.
- Fallback local para desenvolvimento.
- Sessões, rate limiting, privacidade, bloqueios e denúncias.
- Upload de imagem/vídeo até 20 MB para armazenamento local persistente.
- Docker + PostgreSQL para execução reproduzível.
- Estrutura anterior: feed, comunidades, criadores, vídeos, eventos, anúncios e patrocínios.

## Antes de produção
1. Trocar `change-this-password` por segredo forte.
2. Colocar HTTPS/reverse proxy (Nginx, Caddy ou serviço cloud).
3. Usar armazenamento de objetos (S3-compatible, Cloudflare R2, etc.) em vez do volume local para mídia em escala.
4. Implementar backups automáticos do PostgreSQL.
5. Configurar política de privacidade, termos, idade mínima e processo de remoção de conteúdo.
6. Integrar gateway de pagamento antes de cobrar anunciantes.
7. Testar notificações push Android/iOS.
8. Fazer testes de carga, segurança e recuperação de backups.
9. Configurar domínio e variáveis secretas no provedor de hospedagem.
10. Gerar build Android e completar os requisitos da Play Store.

## Execução local
```bash
docker compose up --build
```
Depois abrir `http://localhost:3000`.
