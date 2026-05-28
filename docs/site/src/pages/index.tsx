import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import CodeBlock from '@theme/CodeBlock';
import styles from './index.module.css';

const iconProps = {
  className: styles.cardIcon,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
};

const IconLayers = () => (
  <svg {...iconProps}>
    <path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z"/>
    <path d="M2 12a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 12"/>
    <path d="M2 17a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 17"/>
  </svg>
);

const IconShieldCheck = () => (
  <svg {...iconProps}>
    <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>
    <path d="m9 12 2 2 4-4"/>
  </svg>
);

const IconZap = () => (
  <svg {...iconProps}>
    <path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>
  </svg>
);

const IconBadgeCheck = () => (
  <svg {...iconProps}>
    <path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z"/>
    <path d="m9 12 2 2 4-4"/>
  </svg>
);

const IconWorkflow = () => (
  <svg {...iconProps}>
    <rect width="8" height="8" x="3" y="3" rx="2"/>
    <path d="M7 11v4a2 2 0 0 0 2 2h4"/>
    <rect width="8" height="8" x="13" y="13" rx="2"/>
  </svg>
);

const IconServer = () => (
  <svg {...iconProps}>
    <rect width="20" height="8" x="2" y="2" rx="2" ry="2"/>
    <rect width="20" height="8" x="2" y="14" rx="2" ry="2"/>
    <line x1="6" x2="6.01" y1="6" y2="6"/>
    <line x1="6" x2="6.01" y1="18" y2="18"/>
  </svg>
);

type Card = {
  title: string;
  body: string;
  Icon: React.ComponentType;
};

const pillars: Card[] = [
  {
    title: 'Scale well',
    body: "Aligned with Ethereum's vision of Gigagas L1 blocks powered by STARK proofs.",
    Icon: IconLayers,
  },
  {
    title: 'Privacy first',
    body: 'Powering enterprise EVM chains with robust core modules and multi-backend proofs.',
    Icon: IconShieldCheck,
  },
  {
    title: 'Performance focussed',
    body: 'Aggressive tuning for different prover backend ISAs like RISC-V with C++ known practices.',
    Icon: IconZap,
  },
];

const capabilities: Card[] = [
  {
    title: 'Prove Ethereum blocks',
    body: 'Generate verifiable proofs for block execution with a workflow designed for performance and correctness.',
    Icon: IconBadgeCheck,
  },
  {
    title: 'Power rollups and validity pipelines',
    body: 'Use Zilkworm outputs as a building block for systems that require verifiable execution and settlement-oriented verification.',
    Icon: IconWorkflow,
  },
  {
    title: 'Run Prover-as-a-Service',
    body: 'Deploy Zilkworm as a proving backend for other teams, chains, or internal products.',
    Icon: IconServer,
  },
];

const exampleCommand = `// Create block proofs in one command
z6m_prover prove --block-number 23456789 --out proof.json
z6m_prover verify proof.json`;

export default function Home(): React.ReactElement {
  return (
    <Layout
      title="Zilkworm"
      description="A native, lightweight, performant ZKEVM core written in C++."
    >
      <main className={styles.main}>
        <section className={styles.hero}>
          <h1 className={styles.heroTitle} aria-label="Zilkworm">
            <img
              className={`${styles.heroLogo} ${styles.heroLogoLight}`}
              src="/img/zilkworm-logo.svg"
              alt=""
              aria-hidden="true"
            />
            <img
              className={`${styles.heroLogo} ${styles.heroLogoDark}`}
              src="/img/zilkworm-logo-white.svg"
              alt=""
              aria-hidden="true"
            />
          </h1>
          <p className={styles.heroTagline}>
            A native, lightweight, performant ZKEVM core written in C++
          </p>

          <div className={styles.announce}>
            <strong>zilkworm-hypercube</strong> is now{' '}
            <a
              href="https://ethproofs.org/clusters/62a74df2-59e5-4501-8aca-75843fcde234"
              target="_blank"
              rel="noopener noreferrer"
            >
              live on ethproofs
            </a>{' '}
            and is 2.5× faster than competition at 100-bits security.
          </div>

          <p className={styles.heroLead}>
            Zilkworm uses native C++ optimization and block-validation proofs with
            RISCV-based provers. It enables end-to-end software to create Ethereum
            block and transaction proofs as easy as:
          </p>

          <div className={styles.code}>
            <CodeBlock language="bash">{exampleCommand}</CodeBlock>
          </div>

          <div className={styles.ctaRow}>
            <Link className={styles.ctaPrimary} to="/documentation/basics/getting-started">
              Get Started
            </Link>
            <Link className={styles.ctaSecondary} to="/documentation">
              Read the docs
            </Link>
          </div>
        </section>

        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Our Mission</h2>
          <div className={styles.cardGrid}>
            {pillars.map(({title, body, Icon}) => (
              <article key={title} className={styles.card}>
                <Icon />
                <h3>{title}</h3>
                <p>{body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>What you can do with Zilkworm</h2>
          <div className={styles.cardGrid}>
            {capabilities.map(({title, body, Icon}) => (
              <article key={title} className={`${styles.card} ${styles.cardLarge}`}>
                <Icon />
                <h3>{title}</h3>
                <p>{body}</p>
              </article>
            ))}
          </div>
        </section>
      </main>
    </Layout>
  );
}
