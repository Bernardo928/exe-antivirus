import type { ReactNode } from "react";
import { Breadcrumbs, Layout } from "../components/Layout";
import { LINKS, SITE } from "../data/site";
import { ExternalLink } from "../components/ui";

const UPDATED = "31 de outubro de 2026";

function LegalPage({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Layout>
      <article className="mx-auto max-w-3xl px-5 pt-32 pb-24 sm:px-8 sm:pt-40">
        <Breadcrumbs current={title} />
        <h1 className="display mt-8 text-5xl leading-[1.02] sm:text-6xl">{title}</h1>
        <p className="mt-4 text-sm text-fumo">Última atualização: {UPDATED}</p>
        <div className="mt-12 space-y-6 leading-relaxed text-creme-2 [&_a]:text-creme [&_a]:underline [&_a]:decoration-mostarda/60 [&_a]:underline-offset-4 [&_h2]:display [&_h2]:pt-6 [&_h2]:text-2xl [&_h2]:text-creme [&_ul]:list-disc [&_ul]:space-y-2 [&_ul]:pl-5">
          {children}
        </div>
      </article>
    </Layout>
  );
}

export function Privacy() {
  return (
    <LegalPage title="Política de privacidade">
      <p>
        Esta política explica como o site do {SITE.name} ({SITE.legalName}, CNPJ {SITE.cnpj}) trata dados pessoais,
        de acordo com a Lei Geral de Proteção de Dados (Lei 13.709/2018).
      </p>
      <h2>O que este site coleta</h2>
      <p>
        Nenhum dado pessoal é pedido ou guardado por este site. Não há formulários, cadastro, login, cookies próprios
        ou ferramentas de análise de visitas.
      </p>
      <h2>Registros técnicos da hospedagem</h2>
      <p>
        Como em qualquer site, o provedor de hospedagem pode registrar dados técnicos de acesso (endereço IP, data e
        hora, navegador) para segurança e funcionamento. Esses registros seguem a política do provedor e o Marco Civil
        da Internet (Lei 12.965/2014).
      </p>
      <h2>Serviços de terceiros</h2>
      <ul>
        <li>
          <strong>Google Maps:</strong> o mapa só é carregado quando você clica em "Carregar mapa". A partir daí o Google
          pode coletar dados conforme a{" "}
          <ExternalLink href="https://policies.google.com/privacy?hl=pt-BR">política de privacidade do Google</ExternalLink>.
        </li>
        <li>
          <strong>iFood, Instagram e TikTok:</strong> os links levam para sites de terceiros, que têm políticas próprias.
          Pedidos e pagamentos acontecem no iFood, não neste site.
        </li>
      </ul>
      <h2>Seus direitos</h2>
      <p>
        Você pode pedir informações sobre o tratamento de dados pessoais pelo telefone{" "}
        <a href={LINKS.phone}>{SITE.phone.display}</a> ou pelo Instagram{" "}
        <ExternalLink href={LINKS.instagram}>{SITE.social.instagramHandle}</ExternalLink>.
      </p>
      <h2>Alterações</h2>
      <p>Se o site passar a coletar dados, esta página será atualizada antes disso acontecer.</p>
    </LegalPage>
  );
}

export function Terms() {
  return (
    <LegalPage title="Termos de uso">
      <p>
        Ao usar este site você concorda com os termos abaixo. O site é mantido por {SITE.legalName}, CNPJ {SITE.cnpj},{" "}
        {SITE.address.full}.
      </p>
      <h2>Finalidade</h2>
      <p>
        O site apresenta a hamburgueria {SITE.name}: endereço, horários, contato e os principais itens do cardápio. Ele
        não vende produtos, não recebe pagamentos e não faz reservas.
      </p>
      <h2>Cardápio, preços e horários</h2>
      <p>
        Itens, preços e disponibilidade podem mudar sem aviso. Os valores oficiais estão no{" "}
        <ExternalLink href={LINKS.ifood}>cardápio do iFood</ExternalLink>. Os horários são de referência; confirme pelo
        telefone <a href={LINKS.phone}>{SITE.phone.display}</a> antes da visita.
      </p>
      <h2>Links externos</h2>
      <p>
        Links para iFood, Google Maps, Instagram e TikTok levam a serviços de terceiros, com termos próprios. O{" "}
        {SITE.name} não responde pelo conteúdo ou funcionamento desses serviços.
      </p>
      <h2>Propriedade intelectual</h2>
      <p>
        Nome, marca, textos e fotos deste site pertencem ao {SITE.name} ou aos seus autores e não podem ser usados sem
        autorização.
      </p>
      <h2>Lei aplicável</h2>
      <p>Estes termos seguem a legislação brasileira. Fica eleito o foro da comarca de São Paulo - SP.</p>
    </LegalPage>
  );
}
