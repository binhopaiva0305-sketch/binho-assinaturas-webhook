# Binho Assinaturas — Webhook de códigos

## O que este projeto faz
- Recebe e-mails enviados pelo webhook.
- Aceita somente remetentes cadastrados em ALLOWED_SENDERS.
- Bloqueia mensagens com termos de alteração de senha/e-mail e recuperação.
- Extrai apenas um código numérico isolado de 4 a 8 dígitos.
- Não mostra o corpo completo do e-mail.
- Protege a página com senha.
- Expira códigos após CODE_TTL_SECONDS (padrão: 10 minutos).

## Variáveis de ambiente
WEBHOOK_TOKEN=um-token-grande-e-secreto
PAGE_PASSWORD=uma-senha-forte
SESSION_SECRET=outra-chave-secreta
ALLOWED_SENDERS=remetente1@exemplo.com,remetente2@exemplo.com
CODE_TTL_SECONDS=600

## Comando de inicialização
gunicorn app:app

## Webhook
URL:
https://SEU-ENDERECO/webhook

Cabeçalho:
X-Webhook-Token: SEU-WEBHOOK-TOKEN

Exemplo de JSON:
{
  "from": "remetente@exemplo.com",
  "subject": "Seu código de verificação",
  "textbody": "Seu código é 123456"
}

IMPORTANTE:
Não coloque uma lista ampla de remetentes. Comece com os remetentes exatos dos serviços que você deseja aceitar.
Teste primeiro com uma conta sem informações importantes.
