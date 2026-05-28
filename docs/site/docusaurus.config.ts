import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Zilkworm Documentation',
  tagline: 'A native, lightweight, performant ZKEVM core written in C++',
  favicon: 'img/favicon.ico',
  url: 'https://zilkworm.erigon.tech',
  baseUrl: '/',
  organizationName: 'erigontech',
  projectName: 'zilkworm',
  trailingSlash: false,
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',
  i18n: {defaultLocale: 'en', locales: ['en']},
  markdown: {mermaid: true},
  themes: ['@docusaurus/theme-mermaid'],

  headTags: [
    {
      tagName: 'link',
      attributes: {rel: 'icon', type: 'image/png', sizes: '16x16', href: '/img/favicon-16x16.png'},
    },
    {
      tagName: 'link',
      attributes: {rel: 'icon', type: 'image/png', sizes: '32x32', href: '/img/favicon-32x32.png'},
    },
    {
      tagName: 'link',
      attributes: {rel: 'apple-touch-icon', sizes: '180x180', href: '/img/apple-touch-icon.png'},
    },
    {
      tagName: 'link',
      attributes: {rel: 'icon', type: 'image/png', sizes: '192x192', href: '/img/android-chrome-192x192.png'},
    },
    {
      tagName: 'link',
      attributes: {rel: 'icon', type: 'image/png', sizes: '512x512', href: '/img/android-chrome-512x512.png'},
    },
    {
      tagName: 'script',
      attributes: {
        async: 'true',
        src: 'https://plausible.io/js/pa-f0yBJLAhWL8OM7MYgPYd4.js',
      },
    },
    {
      tagName: 'script',
      attributes: {},
      innerHTML:
        'window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};plausible.init()',
    },
  ],

  plugins: [
    [
      require.resolve('@easyops-cn/docusaurus-search-local'),
      {
        hashed: true,
        language: ['en'],
        docsRouteBasePath: ['/documentation'],
        indexDocs: true,
        indexBlog: false,
        indexPages: false,
        searchBarPosition: 'right',
      },
    ],
  ],

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          routeBasePath: '/documentation',
          path: 'docs',
        },
        blog: false as false,
        theme: {customCss: './src/css/custom.css'},
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    metadata: [
      {name: 'description', content: 'Official documentation for Zilkworm — a native, lightweight, performant ZKEVM core written in C++.'},
      {property: 'og:type', content: 'website'},
      {property: 'og:site_name', content: 'Zilkworm Documentation'},
      {property: 'og:image', content: 'https://zilkworm.erigon.tech/img/og-image.png'},
      {name: 'twitter:card', content: 'summary_large_image'},
      {name: 'twitter:site', content: '@erigoneth'},
      {name: 'twitter:image', content: 'https://zilkworm.erigon.tech/img/og-image.png'},
    ],
    navbar: {
      logo: {
        alt: 'Zilkworm',
        src: 'img/zilkworm-logo.svg',
        srcDark: 'img/zilkworm-logo-white.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'documentation',
          position: 'left',
          label: 'Documentation',
        },
        {
          to: '/collaborations',
          label: 'Collaborations',
          position: 'left',
        },
        {
          type: 'html',
          position: 'right',
          value: '<a href="https://erigon.tech/blog/" target="_blank" rel="noopener noreferrer" class="navbar-blog-btn" aria-label="Blog">Blog</a>',
        },
        {
          type: 'html',
          position: 'right',
          value: '<a href="https://github.com/erigontech/zilkworm" target="_blank" rel="noopener noreferrer" class="navbar-github-icon" aria-label="GitHub repository"><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg></a>',
        },
      ],
    },
    footer: {style: 'dark', copyright: `© ${new Date().getFullYear()} Erigon Technologies AG`},
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
