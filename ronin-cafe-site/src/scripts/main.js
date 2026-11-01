// Único JS do site: mapa sob demanda e consentimento de analytics (LGPD).
(() => {
  'use strict';

  // Mapa: o iframe do Google só é criado quando a pessoa pede.
  const map = document.querySelector('[data-map]');
  const loadBtn = map && map.querySelector('[data-map-load]');
  if (loadBtn) {
    loadBtn.addEventListener('click', () => {
      const src = map.getAttribute('data-src');
      if (!src || !src.startsWith('https://www.google.com/maps')) return;
      const iframe = document.createElement('iframe');
      iframe.src = src;
      iframe.title = 'Mapa do Google com a localização do Ronin Café';
      iframe.loading = 'lazy';
      iframe.referrerPolicy = 'no-referrer-when-downgrade';
      iframe.setAttribute('allowfullscreen', '');
      map.replaceChildren(iframe);
      iframe.focus();
    });
  }

  // Analytics: só existe se o build recebeu ANALYTICS_PROVIDER.
  const cfg = document.body.dataset;
  if (!cfg.analytics) return;

  const KEY = 'ronin-consent';
  const banner = document.querySelector('[data-consent]');
  const read = () => {
    try { return localStorage.getItem(KEY); } catch { return null; }
  };
  const write = (v) => {
    try { localStorage.setItem(KEY, v); } catch { /* armazenamento bloqueado: escolha vale só nesta visita */ }
  };

  let loaded = false;
  const loadAnalytics = () => {
    if (loaded) return;
    loaded = true;
    const s = document.createElement('script');
    s.defer = true;
    if (cfg.analytics === 'plausible' && /^[a-z0-9.-]+$/i.test(cfg.plausible)) {
      s.src = 'https://plausible.io/js/script.js';
      s.dataset.domain = cfg.plausible;
    } else if (cfg.analytics === 'ga4' && /^G-[A-Z0-9]+$/.test(cfg.ga4)) {
      s.src = `https://www.googletagmanager.com/gtag/js?id=${cfg.ga4}`;
      window.dataLayer = window.dataLayer || [];
      window.gtag = function gtag() { window.dataLayer.push(arguments); };
      window.gtag('js', new Date());
      window.gtag('config', cfg.ga4, { anonymize_ip: true });
    } else {
      return;
    }
    document.head.appendChild(s);
  };

  const choose = (v) => {
    write(v);
    if (banner) banner.hidden = true;
    if (v === 'granted') loadAnalytics();
  };

  if (banner) {
    banner.querySelector('[data-consent-accept]').addEventListener('click', () => choose('granted'));
    banner.querySelector('[data-consent-reject]').addEventListener('click', () => choose('denied'));
  }
  document.querySelectorAll('[data-consent-open]').forEach((b) =>
    b.addEventListener('click', () => { if (banner) banner.hidden = false; }),
  );

  const current = read();
  if (current === 'granted') loadAnalytics();
  else if (current !== 'denied' && banner) banner.hidden = false;
})();
