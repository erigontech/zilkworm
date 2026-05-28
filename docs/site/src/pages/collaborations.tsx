import React from 'react';
import Layout from '@theme/Layout';
import styles from './index.module.css';

export default function Collaborations(): React.ReactElement {
  return (
    <Layout
      title="Collaborations"
      description="Get in touch with the Zilkworm team to explore ways we can boost blockchains with ZK together."
    >
      <main className={styles.main}>
        <section className={styles.hero}>
          <h1 className={styles.heroTagline}>
            Let's boost blockchains with ZK together
          </h1>

          <div className={styles.announce}>
            We are now actively collaborating with the{' '}
            <strong>Ethereum Foundation's zkEVM team</strong> 🚀
          </div>

          <p className={styles.heroLead}>
            Get in touch with our team to explore more ways we can benefit each
            other and the Ethereum collective ecosystem with Zilkworm.
          </p>

          <div className={styles.ctaRow}>
            <a className={styles.ctaPrimary} href="mailto:som@erigon.tech">
              Send us a mail
            </a>
          </div>
        </section>
      </main>
    </Layout>
  );
}
