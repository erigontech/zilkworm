import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import CodeBlock from '@theme/CodeBlock';
import styles from './index.module.css';

const pillars = [
  {
    title: 'Scale well',
    body: "Aligned with Ethereum's vision of Gigagas L1 blocks powered by STARK proofs.",
  },
  {
    title: 'Privacy first',
    body: 'Powering enterprise EVM chains with robust core modules and multi-backend proofs.',
  },
  {
    title: 'Performance focussed',
    body: 'Aggressive tuning for different prover backend ISAs like RISC-V with C++ known practices.',
  },
];

const capabilities = [
  {
    title: 'Prove Ethereum blocks',
    body: 'Generate verifiable proofs for block execution with a workflow designed for performance and correctness.',
  },
  {
    title: 'Power rollups and validity pipelines',
    body: 'Use Zilkworm outputs as a building block for systems that require verifiable execution and settlement-oriented verification.',
  },
  {
    title: 'Run Prover-as-a-Service',
    body: 'Deploy Zilkworm as a proving backend for other teams, chains, or internal products.',
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
            {pillars.map((p) => (
              <article key={p.title} className={styles.card}>
                <h3>{p.title}</h3>
                <p>{p.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>What you can do with Zilkworm</h2>
          <div className={styles.cardGrid}>
            {capabilities.map((c) => (
              <article key={c.title} className={`${styles.card} ${styles.cardLarge}`}>
                <h3>{c.title}</h3>
                <p>{c.body}</p>
              </article>
            ))}
          </div>
        </section>
      </main>
    </Layout>
  );
}
