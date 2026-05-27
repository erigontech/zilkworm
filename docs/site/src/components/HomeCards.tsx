import React from 'react';
import Link from '@docusaurus/Link';
import styles from './HomeCards.module.css';

type Card = {
  title: string;
  body: string;
  to: string;
};

export default function HomeCards({cards}: {cards: Card[]}): React.ReactElement {
  return (
    <div className={styles.grid}>
      {cards.map((c) => (
        <Link key={c.to} to={c.to} className={styles.card}>
          <h3 className={styles.title}>{c.title}</h3>
          <p className={styles.body}>{c.body}</p>
        </Link>
      ))}
    </div>
  );
}
