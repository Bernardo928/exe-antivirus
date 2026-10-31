import { About } from "../components/About";
import { Gallery } from "../components/Gallery";
import { Hero } from "../components/Hero";
import { Contact, Faq, Hours, Location } from "../components/Info";
import { Layout } from "../components/Layout";
import { Menu } from "../components/Menu";

export function Home() {
  return (
    <Layout onHome>
      <Hero />
      <About />
      <Menu />
      <Gallery />
      <Hours />
      <Location />
      <Faq />
      <Contact />
    </Layout>
  );
}
