# Para confirmar com o dono

Nada aqui aparece no site até ser confirmado. Para publicar uma resposta, edite `src/data/site.mjs` (troque `confirmed: false` por `true` e preencha `a`, ou preencha `price`) e rode o build.

## Essencial antes de publicar

1. **Domínio oficial** do site (hoje o build usa `https://ronincafe.example` em canonical, og e sitemap). Rode `SITE_URL=https://seudominio.com.br npm run build`.
2. **Link da ficha no Google** (com place_id), para "Como chegar", "4,8 no Google" e o mapa. Hoje os links fazem uma busca por "Ronin Café, Rua das Palmeiras 420".
3. **Horário**: quarta a domingo, 10h às 18h, segunda e terça fechado? Só o domingo às 10h veio do Google; o resto vem de três matérias e da bio do Instagram. E em feriados?
4. **Logo em vetor (SVG)**. O site escreve "Ronin Café" em texto; o favicon é um "R" provisório.
5. **Fotos**: autorização de uso e crédito do fotógrafo, se houver. Confirmar se as pessoas que aparecem na foto do salão autorizam.

## Cardápio

6. Preço atual de cada item (nenhum preço está no site; os de 2024 estão em RESEARCH.md).
7. Descrição de: pão com ovo, Mc Ronin, tahine latte.
8. O tofu mexido continua no cardápio?
9. Método de preparo do café (UFO Dripper ou V60?) e torrefações atuais. Tem espresso?
10. Irish coffee e outras bebidas alcoólicas continuam?
11. Opções vegetarianas, veganas e sem glúten.

## Perguntas frequentes sem resposta

12. Aceita reserva? (Só achamos "reservas limitadas" no fim de semana de abertura da casa nova.)
13. Aceita pets?
14. Formas de pagamento (Pix, cartões, vale-refeição).
15. Tem Wi-Fi?
16. Acessibilidade: entrada sem degrau, banheiro adaptado.
17. Cobra taxa de serviço?
18. Entrega por iFood ou Rappi?
19. Como funciona a fila: lista na porta, tempo médio, horários mais cheios.

## História e legal

20. O nome vem do rōnin, o samurai sem mestre? Quer contar mais sobre a escolha?
21. Data exata em que a casa da Barra Funda abriu (2024) e em que a de Santa Cecília abriu ("13/06", ano?).
22. Razão social e CNPJ para os termos de uso.
23. E-mail de contato para privacidade (LGPD). Hoje o site indica o Instagram.
24. Telefone ou WhatsApp, se quiserem divulgar.
25. Analytics: vão usar Google Analytics 4 ou Plausible? Qual ID/domínio?

## Verificação da pesquisa

26. A rede do ambiente de desenvolvimento bloqueou a leitura direta de todas as matérias e do Instagram; os fatos vieram de resultados de busca. Abra os links do RESEARCH.md e confira, principalmente a citação de Pedro Nóbrega à ISTOÉ, usada na página Sobre.
