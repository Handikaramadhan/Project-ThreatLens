import type { NewsItem } from "../../lib/api";
import { formatApiDate } from "../../lib/datetime";

export function NewsList({ items }: { items: NewsItem[] }) {
  return (
    <div className="news-list">
      {items.map((item) => (
        <a href={item.url} key={item.url} rel="noreferrer" target="_blank">
          <strong>{item.title}</strong>
          <span>{item.source} - {formatApiDate(item.published_at)}</span>
        </a>
      ))}
    </div>
  );
}
