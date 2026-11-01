// Fonte única dos dados do Ronin Café. Cada fato tem fonte em RESEARCH.md.
// Itens com `confirmed: false` NÃO aparecem no site; o build lista todos como pendências.

export const site = {
  name: 'Ronin Café',
  legalName: 'RONIN CAFÉ', // TODO: confirmar com o dono (razão social / CNPJ para os termos de uso)
  // Domínio: defina SITE_URL no build. TODO: confirmar com o dono o domínio oficial.
  url: (process.env.SITE_URL || 'https://ronincafe.example').replace(/\/$/, ''),
  tagline: 'Cafeteria de cozinheiros em Santa Cecília',
  instagram: 'https://www.instagram.com/ronincafesp/',
  instagramHandle: '@ronincafesp',
  founders: ['Pedro Nóbrega', 'Vitor Ribas'],
  priceRange: 'R$ 40 a 80 por pessoa',
  priceRangeSchema: 'R$40-80',
  rating: { value: '4,8', source: 'Google' }, // Sem contagem fixa de avaliações: ela muda.
  address: {
    street: 'R. das Palmeiras, 420',
    streetFull: 'Rua das Palmeiras, 420',
    district: 'Santa Cecília',
    city: 'São Paulo',
    state: 'SP',
    postalCode: '01226-010',
    country: 'BR',
    plusCode: 'F87X+H2',
  },
  geo: { lat: -23.53607, lng: -46.65249 },
  // TODO: confirmar com o dono / trocar pelos links da ficha oficial (com place_id) no Google.
  links: {
    maps: 'https://www.google.com/maps/search/?api=1&query=Ronin+Caf%C3%A9%2C+Rua+das+Palmeiras+420%2C+S%C3%A3o+Paulo',
    directions: 'https://www.google.com/maps/dir/?api=1&destination=Ronin+Caf%C3%A9%2C+Rua+das+Palmeiras+420%2C+Santa+Cec%C3%ADlia%2C+S%C3%A3o+Paulo',
    reviews: 'https://www.google.com/maps/search/?api=1&query=Ronin+Caf%C3%A9%2C+Rua+das+Palmeiras+420%2C+S%C3%A3o+Paulo',
    mapEmbed: 'https://www.google.com/maps?q=Ronin+Caf%C3%A9,+Rua+das+Palmeiras+420,+S%C3%A3o+Paulo&z=16&output=embed',
  },
  phone: null, // TODO: confirmar com o dono (não encontrado)
  email: null, // TODO: confirmar com o dono (contato para privacidade/LGPD)
};

// Horário: quarta a domingo, 10h às 18h (Viva a Cidade, Data Mercantil, Baudo, bio do Instagram).
// Domingo 10h confirmado no Google Maps. TODO: confirmar com o dono os demais dias e feriados.
export const hours = [
  { day: 'Segunda', schema: 'Monday', open: null },
  { day: 'Terça', schema: 'Tuesday', open: null },
  { day: 'Quarta', schema: 'Wednesday', open: '10:00', close: '18:00' },
  { day: 'Quinta', schema: 'Thursday', open: '10:00', close: '18:00' },
  { day: 'Sexta', schema: 'Friday', open: '10:00', close: '18:00' },
  { day: 'Sábado', schema: 'Saturday', open: '10:00', close: '18:00' },
  { day: 'Domingo', schema: 'Sunday', open: '10:00', close: '18:00' },
];
export const hoursShort = 'Quarta a domingo, 10h às 18h';

// Preços: NENHUM preço atual confirmado. Os de 2024 (casa antiga) estão em RESEARCH.md.
// TODO: confirmar com o dono o preço de cada item; preencha `price` (ex.: 'R$ 32') para exibir.
export const menu = [
  {
    id: 'comida',
    title: 'Comida',
    items: [
      { name: 'Queijo quente', desc: 'Mistura de queijos e caramelo de alho feito na casa.', signature: true, price: null },
      { name: 'Mortadela sando', desc: 'Mortadela na chapa, queijo, picles e maionese kewpie no pão de fermentação natural tostado.', signature: true, price: null },
      { name: 'Pão com ovo', desc: null, price: null }, // TODO: confirmar com o dono a descrição
      { name: 'Mc Ronin', desc: null, price: null }, // TODO: confirmar com o dono a descrição
      { name: 'Tofu mexido', desc: null, price: null }, // TODO: confirmar com o dono se continua no cardápio
    ],
  },
  {
    id: 'doces',
    title: 'Doces',
    items: [
      { name: 'Tiramisù', desc: 'Biscoito champanhe banhado em café extraído a frio, creme de mascarpone e telhas de cacau.', price: null },
      { name: 'Banana bread', desc: 'Vegano e tostado, com caramelo de coco, canela e flor de sal.', price: null },
      { name: 'Bolo black', desc: 'Bolo de chocolate denso com ganache.', price: null },
    ],
  },
  {
    id: 'bebidas',
    title: 'Café e bebidas',
    items: [
      { name: 'Café coado', desc: 'Café filtrado, feito na hora.', price: null }, // TODO: confirmar método (UFO ou V60) e torrefações
      { name: 'Cold brew', desc: 'Café em infusão a frio, por até 15 horas.', price: null },
      { name: 'Tahine latte', desc: null, signature: true, price: null }, // TODO: confirmar com o dono a descrição
    ],
  },
];

export const reviews = [
  { author: 'Duda Ventura', text: 'Sou sempre a favor de optar pelos carros chefes dos lugares. O Ronin é conhecido pelo queijo quente. E entrega o que promete.' },
  { author: 'Lucas Ripardo', text: 'Tive o prazer de ir 2 vezes e amei a experiência: menu delicioso, espaço aconchegante e ótimo atendimento.' },
  { author: 'Path Aun Tôrres', text: 'INCRÍVEEEEEL! eu achei que ia ser só hype mas vale DEMAIS a visita!' },
];

export const transit = [
  { name: 'Metrô Santa Cecília', line: 'Linha 3-Vermelha', distance: 'cerca de 450 m em linha reta' },
  { name: 'Metrô Marechal Deodoro', line: 'Linha 3-Vermelha', distance: 'cerca de 430 m em linha reta' },
];

// FAQ: só entra no site o que tem `confirmed: true`.
export const faq = [
  { q: 'Qual é o horário?', a: 'Quarta a domingo, das 10h às 18h. Segunda e terça a casa fica fechada. Em feriados, confira o Instagram antes de sair.', confirmed: true },
  { q: 'Dá para pedir para viagem?', a: 'Dá. O Ronin atende no salão e para viagem.', confirmed: true },
  { q: 'Quanto custa, em média?', a: 'Entre R$ 40 e R$ 80 por pessoa, segundo o Google.', confirmed: true },
  { q: 'Tem fila?', a: 'Nos horários mais cheios, sim. A organização da fila é um dos pontos que os clientes mais elogiam nas avaliações do Google.', confirmed: true },
  { q: 'O Ronin não ficava na Barra Funda?', a: 'Ficava. A primeira casa era na Rua Dr. Albuquerque Lins, na Barra Funda. Hoje o endereço é Rua das Palmeiras, 420, em Santa Cecília.', confirmed: true },

  // TODO: confirmar com o dono cada resposta abaixo antes de marcar confirmed: true.
  { q: 'Tem espresso?', a: null, confirmed: false }, // fontes dizem só que o forte são os filtrados
  { q: 'Aceita reserva?', a: null, confirmed: false },
  { q: 'Posso levar meu cachorro?', a: null, confirmed: false },
  { q: 'Quais formas de pagamento são aceitas?', a: null, confirmed: false },
  { q: 'Tem Wi-Fi?', a: null, confirmed: false },
  { q: 'O espaço é acessível para cadeira de rodas?', a: null, confirmed: false },
  { q: 'Cobra taxa de serviço?', a: null, confirmed: false },
  { q: 'Entrega por aplicativo (iFood, Rappi)?', a: null, confirmed: false },
];

// Analytics: só carrega após consentimento. Defina no build:
//   ANALYTICS_PROVIDER=plausible PLAUSIBLE_DOMAIN=seudominio.com.br
//   ANALYTICS_PROVIDER=ga4 GA4_ID=G-XXXXXXX
export const analytics = {
  provider: process.env.ANALYTICS_PROVIDER || '',
  ga4Id: process.env.GA4_ID || '',
  plausibleDomain: process.env.PLAUSIBLE_DOMAIN || '',
};
