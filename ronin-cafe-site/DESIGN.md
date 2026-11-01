# Design: Ronin Café

## Direção de arte

Três caminhos, todos tirados das fotos e da pesquisa:

1. **Zine de rōnin.** Vermelho de carimbo, kanji, papel de riso. Puxa o nome para o Japão.
   Problema: a casa quase não usa referência japonesa visual (o japonês está no conceito e na maionese kewpie, não na decoração). Viraria fantasia de sushi bar. Descartado.

2. **Comanda de cozinha.** O site como bilhete de pedido: monoespaçada, papel térmico, números de ordem.
   Bom para o cardápio, mas fica frio e não tem foto que sustente. Sem preços confirmados, a comanda fica vazia.

3. **Concreto e nogueira.** A paleta do próprio salão: parede de concreto queimado, off-white, tampo de madeira, aço, luminária preta com luz âmbar, equipe de preto. Tipografia de letreiro (larga e pesada) contra texto serifado de jornal. As fotos fazem o trabalho.

**Escolhida: 3, com detalhes da 2.** É a que existe de verdade quando alguém entra no Ronin. O vocabulário de comanda (números "01, 02", títulos em caixa alta larga, filetes finos) entra só no cardápio e nos rótulos, onde ajuda a escanear. Nada de clichê japonês além do nome.

## Princípios

- Concreto antes de adjetivo. Cada frase diz o que, onde, quando ou quanto.
- Foto real grande, texto curto. Se não há foto, o layout muda; não se coloca imagem genérica.
- Cantos quase retos (2px). Nenhum botão pílula.
- Movimento mínimo: só transições de cor/foco de 150ms e o abrir do FAQ. Respeita `prefers-reduced-motion`.
- Funciona sem JavaScript. JS só carrega o mapa sob demanda e o consentimento de analytics.

## Tokens

### Cor

| Token | Claro | Escuro | Uso |
|---|---|---|---|
| `--paper` | `#f2eee6` | `#161513` | Fundo (parede off-white / salão à noite) |
| `--paper-2` | `#e7e2d8` | `#201e1b` | Faixas, cartões |
| `--concrete` | `#cfcac0` | `#34312c` | Filetes, bordas |
| `--ink` | `#1a1917` | `#efe9df` | Texto principal (camiseta preta) |
| `--ink-2` | `#55524c` | `#b4ada2` | Texto secundário |
| `--walnut` | `#7f4320` | `#e09a6b` | Links, destaque (tampo de madeira) |
| `--walnut-ink` | `#ffffff` | `#1a1917` | Texto sobre walnut |
| `--amber` | `#d98a2b` | `#e7a24a` | Detalhe gráfico apenas (luz da luminária); nunca texto sobre claro |
| `--black` | `#1a1917` | `#0e0d0c` | Botão primário, barra fixa |

Contraste medido (WCAG 2.1): `--ink` sobre `--paper` 15,2:1; `--ink-2` sobre `--paper` 6,7:1 (sobre `--paper-2` 6,0:1); `--walnut` sobre `--paper` 6,7:1; branco sobre `--walnut` 7,7:1. Escuro: `--ink` 15,1:1; `--ink-2` 8,2:1; `--walnut` 7,8:1. Faixa escura: texto 14,2:1, link 9,0:1. O anel de foco usa `--walnut` (6,7:1), não âmbar (2,4:1, reprovaria o critério 1.4.11).

### Tipografia (2 famílias, self-hosted, woff2, subset latin)

- **Archivo** variável (eixos `wght` 100–900 e `wdth` 62–125). Títulos em `wdth 125` + `wght 800`, caixa alta: lembra letreiro pintado e o traço grosso do logo. Rótulos e botões em `wdth 100`, `wght 600`.
- **Newsreader** variável (`wght` 200–800). Texto corrido e descrições do cardápio. Serifada de jornal: dá calor sem enfeite.

Escala (clamp fluido, base 18px no corpo):

| Token | Valor |
|---|---|
| `--step--1` | 0.875rem |
| `--step-0` | 1.0625rem → 1.125rem |
| `--step-1` | 1.25rem → 1.5rem |
| `--step-2` | 1.5rem → 2rem |
| `--step-3` | 2rem → 3rem |
| `--step-4` | 2.5rem → 4.75rem |

### Espaço e forma

- Espaçamento em múltiplos de 4px: `--s-1` 0.25rem até `--s-8` 6rem.
- `--radius: 2px`. `--rule: 1px solid var(--concrete)`.
- Largura de leitura `--measure: 62ch`. Conteúdo máx. `--max: 76rem`. Gutter mínimo 16px no celular.

## Componentes

- **Cabeçalho**: nome em Archivo largo, 3 links (Cardápio, Sobre, Visite) e ícone do Instagram. Cabe em 390px sem menu hambúrguer.
- **Botões**: retangulares, 48px de altura mínima. Primário preto, secundário com borda.
- **Barra fixa no celular**: "Como chegar" + "Instagram", some em telas ≥ 900px.
- **Item de cardápio**: número de ordem, nome em caixa alta larga, descrição serifada, selo "carro-chefe" quando a fonte confirma.
- **FAQ**: `<details>` nativo, sem JS.
- **Mapa**: placeholder com endereço e botão "Mostrar mapa"; o iframe do Google só carrega no clique (zero requisições de terceiros antes disso).
- **Ícones**: Lucide (ISC), SVG inline, `stroke-width 1.75`.

## Fotos

| Arquivo | Onde | Por quê |
|---|---|---|
| salao-clientes | Hero (home) | Mostra gente comendo, equipe e salão: prova social sem número inventado |
| bandeja-lanches | Home "O que pedir", og:image | Logo gravado na bandeja + lanches |
| mesa-vista-de-cima | Home "O que pedir", cardápio | Mesa cheia: cafés, drinques, sanduíches |
| mesa-oval-concreto | Sobre, home "A casa" | Concreto, madeira e luz: o ambiente |
| ovos-pao-fermentacao | Cardápio | Prato de cozinha, não só lanche |
| rabanada-morango | Cardápio | Doce |
