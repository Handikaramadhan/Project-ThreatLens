import type { NewsItem } from "../../lib/api";

export function NewsList({ items }: { items: NewsItem[] }) {
  return (
    <div className="news-list">
      {items.map((item) => (
        <a href={item.url} key={item.url} rel="noreferrer" target="_blank">
          <strong>{item.title}</strong>
          <span>{item.source} - {new Date(item.published_at).toLocaleDateString("id-ID")}</span>
        </a>
      ))}
    </div>
  );
}
