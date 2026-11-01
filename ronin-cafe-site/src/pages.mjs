import { site, hours, hoursShort, menu, reviews, transit, faq } from './data/site.mjs';
import { icon } from './lib/icons.mjs';
import { picture, preloadTag } from './lib/images.mjs';
import { esc, breadcrumbs, localBusinessSchema } from './lib/layout.mjs';

const ext = 'rel="noopener" target="_blank"';
const newTab = '<span class="sr-only"> (abre em nova aba)</span>';

const ratingBadge = () =>
  `<a class="rating" href="${site.links.reviews}" ${ext}>${icon('star', { size: 16 })}<strong>${site.rating.value}</strong> no Google<span class="sr-only">: ver avaliações no Google Maps, abre em nova aba</span></a>`;

const HERO_SIZES = '(min-width: 900px) 44vw, 100vw';

/* ---------------- Home ---------------- */
function home() {
  const signatures = menu.flatMap((s) => s.items).filter((i) => i.signature);
  const confirmedFaq = faq.filter((f) => f.confirmed).slice(0, 4);
  return {
    path: '/',
    title: 'Ronin Café | Queijo quente e café coado em Santa Cecília, SP',
    description: 'Cafeteria de cozinheiros na Rua das Palmeiras, 420, Santa Cecília, São Paulo. Queijo quente com caramelo de alho, mortadela sando e café coado. Quarta a domingo, 10h às 18h.',
    // No celular a foto fica abaixo da dobra: o LCP é o texto, então o preload só vale no desktop.
    preload: preloadTag('salao-clientes', HERO_SIZES, '(min-width: 900px)'),
    schemas: [localBusinessSchema()],
    body: `
<section class="hero wrap" aria-labelledby="hero-title">
  <div class="hero-text">
    <p class="eyebrow">${icon('mapPin', { size: 16 })}Santa Cecília, São Paulo</p>
    <h1 id="hero-title" class="display">Cafeteria de cozinheiros na Rua das Palmeiras</h1>
    <p class="lede">O Ronin é dos chefs Pedro Nóbrega e Vitor Ribas, que passaram pelo Notiê. A fama é do queijo quente com caramelo de alho. Também tem mortadela sando, tahine latte e café coado.</p>
    <ul class="facts">
      <li>${icon('clock', { size: 18 })}<span>${hoursShort}</span></li>
      <li>${icon('mapPin', { size: 18 })}<span>${site.address.street}</span></li>
      <li>${icon('bag', { size: 18 })}<span>No salão ou para viagem, R$ 40 a 80 por pessoa</span></li>
    </ul>
    <div class="actions">
      <a class="btn btn--primary" href="${site.links.directions}" ${ext}>${icon('navigation', { size: 18 })}Como chegar${newTab}</a>
      <a class="btn btn--ghost" href="/cardapio/">Ver cardápio${icon('arrowRight', { size: 18 })}</a>
    </div>
    ${ratingBadge()}
  </div>
  <figure class="hero-media">
    ${picture('salao-clientes', { sizes: HERO_SIZES, priority: 'desktop', className: 'cover' })}
  </figure>
</section>

<section class="band" aria-labelledby="pedir-title">
  <div class="wrap split">
    <div class="split-text">
      <p class="label">O que pedir</p>
      <h2 id="pedir-title" class="h2">Os pedidos de quem já foi</h2>
      <ol class="picks">
        ${signatures
          .map(
            (i, n) => `<li>
          <span class="pick-num" aria-hidden="true">${String(n + 1).padStart(2, '0')}</span>
          <div><h3 class="item-name">${esc(i.name)}</h3>${i.desc ? `<p>${esc(i.desc)}</p>` : ''}</div>
        </li>`,
          )
          .join('')}
      </ol>
      <a class="text-link" href="/cardapio/">Cardápio completo${icon('arrowRight', { size: 16 })}</a>
    </div>
    <div class="photo-pair">
      <figure class="pp-a">${picture('bandeja-lanches', { sizes: '(min-width: 900px) 40vw, 100vw' })}</figure>
      <figure class="pp-b">${picture('mesa-vista-de-cima', { sizes: '(min-width: 900px) 22vw, 50vw' })}</figure>
    </div>
  </div>
</section>

<section class="wrap reviews" aria-labelledby="reviews-title">
  <div class="section-head">
    <h2 id="reviews-title" class="h2">O que dizem no Google</h2>
    ${ratingBadge()}
  </div>
  <ul class="review-list">
    ${reviews
      .map(
        (r) => `<li><figure>
      <blockquote><p>${esc(r.text)}</p></blockquote>
      <figcaption>${esc(r.author)}, <a href="${site.links.reviews}" ${ext}>no Google${newTab}</a></figcaption>
    </figure></li>`,
      )
      .join('')}
  </ul>
</section>

<section class="band band--dark" aria-labelledby="casa-title">
  <div class="wrap split split--reverse">
    <figure class="casa-photo">${picture('mesa-oval-concreto', { sizes: '(min-width: 900px) 40vw, 100vw' })}</figure>
    <div class="split-text">
      <p class="label">A casa</p>
      <h2 id="casa-title" class="h2">Concreto, madeira e balcão à vista</h2>
      <p>O Ronin nasceu na Barra Funda e mudou para Santa Cecília. A proposta continua a mesma: dois cozinheiros com liberdade para cozinhar. O café é bom e honesto; a comida é o centro.</p>
      <a class="text-link" href="/sobre/">A história do Ronin${icon('arrowRight', { size: 16 })}</a>
    </div>
  </div>
</section>

<section class="wrap visit-strip" aria-labelledby="visita-title">
  <h2 id="visita-title" class="h2">Antes de ir</h2>
  <div class="visit-grid">
    <div class="visit-card">
      ${icon('mapPin', { size: 22 })}
      <h3 class="item-name">Endereço</h3>
      <p>${site.address.street}, ${site.address.district}. A uns 450 m dos metrôs Santa Cecília e Marechal Deodoro.</p>
    </div>
    <div class="visit-card">
      ${icon('clock', { size: 22 })}
      <h3 class="item-name">Horário</h3>
      <p>${hoursShort}. Segunda e terça, fechado.</p>
    </div>
    <div class="visit-card">
      ${icon('users', { size: 22 })}
      <h3 class="item-name">Fila</h3>
      <p>Nos horários cheios tem fila, e ela é bem organizada: é um dos pontos mais elogiados nas avaliações.</p>
    </div>
  </div>
  <div class="actions">
    <a class="btn btn--primary" href="/visite/">Mapa e como chegar${icon('arrowRight', { size: 18 })}</a>
  </div>
  <div class="faq-teaser">
    <h3 class="label">Perguntas frequentes</h3>
    ${faqList(confirmedFaq, 4)}
    <a class="text-link" href="/visite/#perguntas">Todas as perguntas${icon('arrowRight', { size: 16 })}</a>
  </div>
</section>`,
  };
}

function faqList(items, level = 3) {
  return `<div class="faq">${items
    .map(
      (f) => `<details>
    <summary><h${level} class="faq-q">${esc(f.q)}</h${level}>${icon('plus', { size: 20 })}</summary>
    <p>${esc(f.a)}</p>
  </details>`,
    )
    .join('')}</div>`;
}

/* ---------------- Cardápio ---------------- */
function cardapio() {
  const bc = breadcrumbs([{ name: 'Cardápio', href: '/cardapio/' }]);
  let n = 0;
  const menuSchema = {
    '@context': 'https://schema.org',
    '@type': 'Menu',
    name: 'Cardápio do Ronin Café',
    url: `${site.url}/cardapio/`,
    hasMenuSection: menu.map((s) => ({
      '@type': 'MenuSection',
      name: s.title,
      hasMenuItem: s.items.map((i) => ({ '@type': 'MenuItem', name: i.name, ...(i.desc ? { description: i.desc } : {}) })),
    })),
  };
  return {
    path: '/cardapio/',
    title: 'Cardápio: queijo quente, mortadela sando e café coado',
    description: 'Os pratos do Ronin Café em Santa Cecília: queijo quente com caramelo de alho, mortadela sando com maionese kewpie, tiramisù, banana bread, tahine latte e café coado.',
    schemas: [bc.schema, menuSchema],
    body: `
${bc.html}
<header class="page-head wrap">
  <h1 class="display display--page">Cardápio</h1>
  <p class="lede">O cardápio é de cozinheiro e muda. Aqui estão os pratos que a casa e a imprensa já confirmaram. Os preços do dia ficam no balcão e no <a href="${site.instagram}" ${ext}>Instagram${newTab}</a>.</p>
</header>
<div class="wrap menu-layout">
  <div class="menu">
    ${menu
      .map(
        (s) => `<section class="menu-section" aria-labelledby="m-${s.id}">
      <h2 id="m-${s.id}" class="h2 menu-title">${esc(s.title)}</h2>
      <ul class="menu-items">
        ${s.items
          .map((i) => {
            n += 1;
            return `<li class="menu-item">
          <span class="pick-num" aria-hidden="true">${String(n).padStart(2, '0')}</span>
          <div class="menu-item-body">
            <h3 class="item-name">${esc(i.name)}${i.signature ? ' <span class="tag">Carro-chefe</span>' : ''}</h3>
            ${i.desc ? `<p>${esc(i.desc)}</p>` : ''}
          </div>
          ${i.price ? `<span class="price">${esc(i.price)}</span>` : ''}
        </li>`;
          })
          .join('')}
      </ul>
    </section>`,
      )
      .join('')}
    <p class="note">Tem restrição alimentar? Fale com a equipe antes de pedir.</p>
  </div>
  <aside class="menu-photos" aria-label="Fotos de pratos">
    <figure>${picture('ovos-pao-fermentacao', { sizes: '(min-width: 900px) 30vw, 100vw' })}</figure>
    <figure>${picture('rabanada-morango', { sizes: '(min-width: 900px) 30vw, 100vw' })}</figure>
    <p class="note">Pratos fotografados no salão. Pergunte o que está saindo no dia.</p>
  </aside>
</div>
<section class="wrap cross" aria-label="Continue">
  <a class="cross-link" href="/visite/"><span class="label">Próximo passo</span><span class="h3">Como chegar e horário</span>${icon('arrowRight', { size: 22 })}</a>
  <a class="cross-link" href="/sobre/"><span class="label">Quem cozinha</span><span class="h3">A história do Ronin</span>${icon('arrowRight', { size: 22 })}</a>
</section>`,
  };
}

/* ---------------- Sobre ---------------- */
function sobre() {
  const bc = breadcrumbs([{ name: 'Sobre', href: '/sobre/' }]);
  return {
    path: '/sobre/',
    title: 'Sobre: Pedro Nóbrega, Vitor Ribas e a história do Ronin',
    description: 'O Ronin Café é dos cozinheiros Pedro Nóbrega e Vitor Ribas, que passaram pelo Notiê. Abriu na Barra Funda e hoje fica na Rua das Palmeiras, em Santa Cecília.',
    schemas: [bc.schema],
    body: `
${bc.html}
<header class="page-head wrap">
  <h1 class="display display--page">Dois cozinheiros e uma cafeteria</h1>
  <p class="lede">O Ronin é de Pedro Nóbrega e Vitor Ribas. Os dois trabalharam em cozinhas de restaurante em São Paulo, entre elas a do Notiê, até abrir uma casa onde pudessem cozinhar do jeito deles.</p>
</header>
<div class="wrap prose-layout">
  <article class="prose">
    <h2 class="h2">O nome</h2>
    <p>Rōnin era o samurai sem mestre. A casa se apresenta como "cafeteria de cozinheiros", e é isso: o café leva o nome, mas quem manda é a cozinha.</p>

    <h2 class="h2">Da Barra Funda para Santa Cecília</h2>
    <p>A primeira casa abriu em 2024 na Rua Dr. Albuquerque Lins, na divisa da Barra Funda com Santa Cecília. Em setembro daquele ano, a <a href="https://istoe.com.br/dois-cozinheiros-mostram-o-ronin-muito-alem-do-cafe" ${ext}>ISTOÉ${newTab}</a> já escrevia que ali o café era "coadjuvante". Depois, o Ronin mudou para a Rua das Palmeiras, 420, o endereço atual.</p>

    <blockquote class="pull">
      <p>"Não somos uma cafeteria que oferece trocentos métodos de extração, mas temos um café bom e honesto."</p>
      <footer>Pedro Nóbrega, à <a href="https://istoe.com.br/dois-cozinheiros-mostram-o-ronin-muito-alem-do-cafe" ${ext}>ISTOÉ${newTab}</a></footer>
    </blockquote>

    <h2 class="h2">O que sai da cozinha</h2>
    <p>O queijo quente com caramelo de alho virou o pedido mais famoso. O mortadela sando junta mortadela na chapa, queijo, picles e maionese kewpie no pão de fermentação natural. Nos doces, tiramisù com café extraído a frio e banana bread vegano. <a href="/cardapio/">Veja o cardápio</a>.</p>

    <h2 class="h2">Fontes</h2>
    <ul class="sources">
      <li><a href="https://istoe.com.br/dois-cozinheiros-mostram-o-ronin-muito-alem-do-cafe" ${ext}>ISTOÉ: Dois cozinheiros mostram o Ronin muito além do café (2024)${newTab}</a></li>
      <li><a href="https://revistaespresso.com.br/cafeterias/ronin-cafe-sao-paulo-sp/" ${ext}>Revista Espresso: Ronin Café${newTab}</a></li>
      <li><a href="https://www.terra.com.br/vida-e-estilo/degusta/ronin-uma-cafeteria-de-cozinheiros-estreia-na-barra-funda,3209bab863b8f8bb9667ff8aba890fd44lrgjpum.html" ${ext}>Terra: Ronin, uma cafeteria de cozinheiros, estreia na Barra Funda${newTab}</a></li>
      <li><a href="https://vivaacidadenews.com.br/events/novas-cafeterias-santa-cecilia/" ${ext}>Viva a Cidade: Santa Cecília ganha três novas cafeterias${newTab}</a></li>
    </ul>
  </article>
  <figure class="prose-photo">
    ${picture('mesa-oval-concreto', { sizes: '(min-width: 900px) 34vw, 100vw' })}
  </figure>
</div>
<section class="wrap cross" aria-label="Continue">
  <a class="cross-link" href="/cardapio/"><span class="label">Para pedir</span><span class="h3">Ver o cardápio</span>${icon('arrowRight', { size: 22 })}</a>
  <a class="cross-link" href="/visite/"><span class="label">Para ir</span><span class="h3">Endereço, mapa e horário</span>${icon('arrowRight', { size: 22 })}</a>
</section>`,
  };
}

/* ---------------- Visite ---------------- */
function visite() {
  const bc = breadcrumbs([{ name: 'Visite', href: '/visite/' }]);
  const confirmed = faq.filter((f) => f.confirmed);
  const faqSchema = {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: confirmed.map((f) => ({ '@type': 'Question', name: f.q, acceptedAnswer: { '@type': 'Answer', text: f.a } })),
  };
  return {
    path: '/visite/',
    title: 'Visite: endereço, horário, mapa e como chegar',
    description: 'Ronin Café: Rua das Palmeiras, 420, Santa Cecília, São Paulo. Quarta a domingo, 10h às 18h. Perto dos metrôs Santa Cecília e Marechal Deodoro. Mapa, fila e perguntas frequentes.',
    schemas: [bc.schema, localBusinessSchema(), faqSchema],
    body: `
${bc.html}
<header class="page-head wrap">
  <h1 class="display display--page">Visite o Ronin</h1>
  <p class="lede">${site.address.streetFull}, ${site.address.district}, ${site.address.city}. ${hoursShort}.</p>
  <div class="actions">
    <a class="btn btn--primary" href="${site.links.directions}" ${ext}>${icon('navigation', { size: 18 })}Rotas no Google Maps${newTab}</a>
    <a class="btn btn--ghost" href="${site.instagram}" ${ext}>${icon('instagram', { size: 18 })}${site.instagramHandle}${newTab}</a>
  </div>
</header>

<div class="wrap visit-layout">
  <div class="map" data-map data-src="${site.links.mapEmbed}">
    <div class="map-placeholder">
      ${icon('map', { size: 32 })}
      <p><strong>${site.address.street}</strong><br>${site.address.district}, ${site.address.city}, ${site.address.state}, ${site.address.postalCode}</p>
      <button type="button" class="btn btn--ghost" data-map-load>Mostrar mapa</button>
      <p class="map-hint">O mapa vem do Google e só carrega se você clicar.</p>
    </div>
  </div>

  <div class="visit-info">
    <section aria-labelledby="h-horario">
      <h2 id="h-horario" class="h3">${icon('clock', { size: 20 })}Horário</h2>
      <table class="hours">
        <caption class="sr-only">Horário de funcionamento</caption>
        <tbody>
        ${hours
          .map((h) => `<tr><th scope="row">${h.day}</th><td>${h.open ? `${h.open.replace(':00', 'h')} às ${h.close.replace(':00', 'h')}` : 'Fechado'}</td></tr>`)
          .join('')}
        </tbody>
      </table>
      <p class="note">Em feriados o horário pode mudar. Confira no <a href="${site.instagram}" ${ext}>Instagram${newTab}</a>.</p>
    </section>

    <section aria-labelledby="h-chegar">
      <h2 id="h-chegar" class="h3">${icon('train', { size: 20 })}Transporte público</h2>
      <ul class="transit">
        ${transit.map((t) => `<li><strong>${t.name}</strong> (${t.line}), ${t.distance}</li>`).join('')}
      </ul>
    </section>

    <section aria-labelledby="h-fila">
      <h2 id="h-fila" class="h3">${icon('users', { size: 20 })}Fila</h2>
      <p>Nos horários cheios pode ter espera. A organização da fila é um dos pontos mais elogiados nas avaliações do Google.</p>
      <!-- TODO: confirmar com o dono como a fila funciona (lista de espera, nome na porta, tempo médio). -->
    </section>
  </div>
</div>

<section class="wrap faq-section" id="perguntas" aria-labelledby="faq-title">
  <h2 id="faq-title" class="h2">Perguntas frequentes</h2>
  ${faqList(confirmed, 3)}
  <p class="note">Não achou a resposta? Mande mensagem no <a href="${site.instagram}" ${ext}>Instagram${newTab}</a>.</p>
</section>
<section class="wrap cross" aria-label="Continue">
  <a class="cross-link" href="/cardapio/"><span class="label">Antes de ir</span><span class="h3">Ver o cardápio</span>${icon('arrowRight', { size: 22 })}</a>
  <a class="cross-link" href="/sobre/"><span class="label">Quem cozinha</span><span class="h3">A história do Ronin</span>${icon('arrowRight', { size: 22 })}</a>
</section>`,
  };
}

/* ---------------- Legal ---------------- */
function privacidade() {
  const bc = breadcrumbs([{ name: 'Privacidade', href: '/privacidade/' }]);
  return {
    path: '/privacidade/',
    title: 'Política de privacidade',
    description: 'Como o site do Ronin Café trata dados pessoais, cookies e o mapa do Google, conforme a LGPD.',
    schemas: [bc.schema],
    body: `
${bc.html}
<header class="page-head wrap"><h1 class="display display--page">Política de privacidade</h1><p class="lede">Última atualização: novembro de 2026.</p></header>
<article class="wrap prose prose--legal">
  <h2 class="h3">Resumo</h2>
  <p>Este site não tem cadastro, login nem formulário. Não pedimos seu nome, e-mail ou telefone.</p>

  <h2 class="h3">Medição de visitas</h2>
  <p>Podemos usar uma ferramenta de medição de audiência (Google Analytics 4 ou Plausible) para saber quantas pessoas visitam o site e quais páginas leem. Ela só é ativada depois que você clica em "Permitir" no aviso de cookies. Se recusar, nada é carregado. Você pode mudar a escolha a qualquer momento pelo link "Preferências de cookies" no rodapé, quando a medição estiver ativa.</p>
  <p>A base legal é o seu consentimento (art. 7º, I, da Lei 13.709/2018, a LGPD).</p>

  <h2 class="h3">O que fica no seu navegador</h2>
  <p>Guardamos apenas a sua escolha sobre cookies (chave <code>ronin-consent</code> no armazenamento local do navegador). Ela não sai do seu aparelho.</p>

  <h2 class="h3">Mapa do Google</h2>
  <p>Na página Visite, o mapa só é carregado se você clicar em "Mostrar mapa". A partir daí, o Google recebe dados da sua conexão, conforme a <a href="https://policies.google.com/privacy?hl=pt-BR" rel="noopener" target="_blank">política de privacidade do Google${newTab}</a>.</p>

  <h2 class="h3">Links externos</h2>
  <p>Links para Instagram e Google Maps levam a serviços de terceiros, com políticas próprias.</p>

  <h2 class="h3">Seus direitos</h2>
  <p>Você pode pedir acesso, correção ou exclusão de dados pessoais, nos termos do art. 18 da LGPD. Para isso, fale com a gente pelo <a href="${site.instagram}" ${ext}>Instagram ${site.instagramHandle}${newTab}</a>.</p>
  <!-- TODO: confirmar com o dono um e-mail de contato para privacidade (encarregado/LGPD). -->
</article>`,
  };
}

function termos() {
  const bc = breadcrumbs([{ name: 'Termos de uso', href: '/termos/' }]);
  return {
    path: '/termos/',
    title: 'Termos de uso',
    description: 'Condições de uso do site do Ronin Café: informações, preços, horários, fotos e links externos.',
    schemas: [bc.schema],
    body: `
${bc.html}
<header class="page-head wrap"><h1 class="display display--page">Termos de uso</h1><p class="lede">Última atualização: novembro de 2026.</p></header>
<article class="wrap prose prose--legal">
  <h2 class="h3">Informações do site</h2>
  <p>Cardápio, horários e preços podem mudar sem aviso. Em caso de diferença, vale o que estiver no balcão do Ronin Café e no Instagram ${site.instagramHandle}.</p>

  <h2 class="h3">Fotos e textos</h2>
  <p>As fotos e os textos deste site pertencem ao Ronin Café. Não use sem autorização. As avaliações citadas são de clientes no Google, reproduzidas sem edição e com link para a fonte.</p>

  <h2 class="h3">Links externos</h2>
  <p>Não respondemos pelo conteúdo de sites de terceiros, como Google Maps, Instagram e veículos de imprensa.</p>

  <h2 class="h3">Contato</h2>
  <p>Dúvidas sobre estes termos: <a href="${site.instagram}" ${ext}>Instagram ${site.instagramHandle}${newTab}</a>.</p>
  <!-- TODO: confirmar com o dono a razão social e o CNPJ para incluir aqui. -->
</article>`,
  };
}

function notFound() {
  return {
    path: '/404.html',
    file: '404.html',
    title: 'Página não encontrada',
    description: 'Esta página não existe no site do Ronin Café.',
    noindex: true,
    body: `
<section class="wrap not-found">
  <p class="label">Erro 404</p>
  <h1 class="display display--page">Esse pedido não saiu da cozinha</h1>
  <p class="lede">A página que você procurou não existe ou mudou de lugar. O Ronin também mudou: agora fica na ${site.address.streetFull}, em Santa Cecília.</p>
  <div class="actions">
    <a class="btn btn--primary" href="/">Ir para o início</a>
    <a class="btn btn--ghost" href="/cardapio/">Ver cardápio</a>
    <a class="btn btn--ghost" href="/visite/">Como chegar</a>
  </div>
</section>`,
  };
}

export const buildPages = () => [home(), cardapio(), sobre(), visite(), privacidade(), termos(), notFound()];
