# Instruções para o Claude

## Criação de sites

Sempre que o usuário pedir para criar um site (landing page, página web, web app, interface HTML
ou qualquer variação), use a skill `apple-design` (`.claude/skills/apple-design/SKILL.md`):

1. **Antes de escrever código**, siga o "Design improvement mode" da skill: defina o assunto, o
   público e o trabalho único da página; monte o sistema de tokens (4–6 cores com contraste
   calculado em claro e escuro, escala tipográfica, layout com wireframe ASCII, um elemento
   assinatura, no máximo um momento de animação).
2. **Critique o plano**: se ele serviria para qualquer outro produto, é um template — revise.
   Evite os três visuais genéricos citados na skill (creme + serifa + terracota; quase-preto +
   um acento ácido; jornal com linhas finas e raio zero).
3. **Construa** respeitando o piso de qualidade: contraste 4,5:1 para texto normal e 3:1 para
   texto grande, alvos de toque de 44×44 px, texto que escala, modo claro e escuro, foco visível
   no teclado, `prefers-reduced-motion` e `prefers-reduced-transparency`, responsivo até 320 px.
4. **Revise o resultado** com as cinco lentes da skill (acessibilidade, convenções, craft,
   interação, texto) e corrija o que for Critical ou High antes de entregar.

Para sites, valem os princípios e os fundamentos (acessibilidade, cor, tipografia, layout,
escrita), não as convenções específicas de iOS/macOS.

Observação: a pasta `references/` citada na skill (páginas da HIG) não está neste repositório.
Quando ela não estiver disponível, marque as afirmações como julgamento próprio em vez de citar
arquivos.
