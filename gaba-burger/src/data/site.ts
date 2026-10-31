/**
 * Dados do estabelecimento. Tudo aqui foi informado pelo cliente ou encontrado
 * em fontes públicas. Não acrescente preços, ingredientes ou números sem
 * confirmação: o site mostra exatamente o que estiver neste arquivo.
 */

export const SITE = {
  name: "Gaba Burger",
  legalName: "Gaba Burger Ltda",
  cnpj: "51.168.619/0001-40",
  owner: "Gabriel Bruno",
  ownerNickname: "Gaba",
  neighborhood: "Pinheiros",
  city: "São Paulo",
  address: {
    street: "Rua Mourato Coelho, 833",
    district: "Pinheiros",
    city: "São Paulo",
    state: "SP",
    postalCode: "05417-011",
    country: "BR",
    full: "Rua Mourato Coelho, 833, Pinheiros, São Paulo - SP, 05417-011",
  },
  phone: {
    display: "(11) 93912-3396",
    e164: "+5511939123396",
  },
  priceRange: "R$ 60 a 80 por pessoa",
  rating: {
    value: "4,8",
    count: 272,
    source: "Google",
  },
  social: {
    instagramHandle: "@gababruno",
  },
} as const;

export const LINKS = {
  maps: "https://maps.app.goo.gl/5RhbCB2ajdyRvZ2q9",
  directions:
    "https://www.google.com/maps/dir/?api=1&destination=" +
    encodeURIComponent("Gaba Burger, Rua Mourato Coelho, 833, Pinheiros, São Paulo - SP, 05417-011"),
  mapEmbed:
    "https://www.google.com/maps?output=embed&q=" +
    encodeURIComponent("Gaba Burger, Rua Mourato Coelho, 833, Pinheiros, São Paulo - SP"),
  ifood:
    "https://www.ifood.com.br/delivery/sao-paulo-sp/gaba-burger-pinheiros/fa5920b6-610a-4f51-9607-7b4c5fff875d",
  instagram: "https://www.instagram.com/gababruno/",
  tiktok: "https://www.tiktok.com/@gababruno",
  phone: "tel:+5511939123396",
} as const;

export type MenuItem = {
  id: string;
  name: string;
  tag?: string;
  /** Observação de disponibilidade exibida no card. */
  availability?: string;
  ingredients: string[];
  /** Somente preencha com preço confirmado no iFood. Ex.: "R$ 42,90". */
  price?: string;
};

export const MENU: MenuItem[] = [
  {
    id: "gaba-tasty",
    name: "Gaba Tasty",
    tag: "Clássico da casa",
    ingredients: ["Hambúrguer grelhado de 180g", "Queijo americano", "Maionese da casa"],
  },
  {
    id: "gaba-melt",
    name: "Gaba Melt",
    tag: "Clássico da casa",
    ingredients: ["Hambúrguer de 180g", "Cheddar", "Bacon", "Cebola caramelizada"],
  },
  {
    id: "lua-cheia",
    name: "Lua Cheia",
    tag: "Burger do mês",
    availability: "O burger do mês muda. Confira no iFood se ainda está no cardápio.",
    ingredients: ["Rúcula", "Maionese de estilo asiático"],
  },
  {
    id: "pineapple-burger",
    name: "Pineapple Burger",
    tag: "Edição limitada",
    availability: "Edição limitada. Disponibilidade não confirmada.",
    ingredients: ["Burger com abacaxi, lançado como edição especial"],
  },
];

export const NAV = [
  { id: "inicio", label: "Início" },
  { id: "sobre", label: "Sobre" },
  { id: "cardapio", label: "Cardápio" },
  { id: "galeria", label: "Galeria" },
  { id: "horarios", label: "Horários" },
  { id: "localizacao", label: "Localização" },
  { id: "contato", label: "Contato" },
] as const;

export const FAQ = [
  {
    q: "Onde fica o Gaba Burger?",
    a: "Na Rua Mourato Coelho, 833, em Pinheiros, São Paulo (CEP 05417-011).",
  },
  {
    q: "Quais dias a casa abre?",
    a: "De quarta a domingo. Segunda e terça a casa fica fechada. Sábado e domingo também tem almoço, das 12h às 16h.",
  },
  {
    q: "Tem delivery?",
    a: "Sim, pelo iFood. Os preços e o cardápio atualizado também estão lá.",
  },
  {
    q: "Os horários podem mudar?",
    a: "Podem, principalmente em feriados. Antes de ir, confirme pelo telefone (11) 93912-3396 ou no Instagram @gababruno.",
  },
  {
    q: "Quem está por trás da casa?",
    a: "Gabriel Bruno, o Gaba, criador de conteúdo conhecido pelos vídeos em que viaja provando comida pelo Brasil.",
  },
] as const;
