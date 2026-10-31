import { Layout } from "../components/Layout";

export function NotFound() {
  return (
    <Layout>
      <section className="mx-auto flex min-h-[80vh] max-w-3xl flex-col justify-center px-5 pt-32 pb-24 sm:px-8">
        <p className="eyebrow">Erro 404</p>
        <h1 className="display mt-6 text-6xl leading-[0.95] sm:text-8xl">
          Essa página <em className="text-mostarda">saiu da chapa</em>.
        </h1>
        <p className="mt-8 max-w-lg text-lg leading-relaxed text-creme-2">
          O endereço que você abriu não existe ou mudou de lugar. O cardápio e o endereço da casa continuam aqui.
        </p>
        <div className="mt-10 flex flex-col gap-3 sm:flex-row">
          <a href="/" className="btn btn-primary">Voltar ao início</a>
          <a href="/#cardapio" className="btn btn-ghost">Ver cardápio</a>
        </div>
      </section>
    </Layout>
  );
}
