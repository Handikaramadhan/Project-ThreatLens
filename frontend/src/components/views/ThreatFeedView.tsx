import { CalendarDays, ExternalLink, Globe2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { NewsItem } from "../../lib/api";
import { formatApiDate, formatApiDateTime } from "../../lib/datetime";
import { EmptyState } from "../ui/EmptyState";
import { Panel } from "../ui/Panel";

function hostname(url: string) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

export function ThreatFeedView({ news }: { news: NewsItem[] }) {
  const [selectedUrl, setSelectedUrl] = useState(news[0]?.url ?? "");

  useEffect(() => {
    if (!news.some((item) => item.url === selectedUrl)) {
      setSelectedUrl(news[0]?.url ?? "");
    }
  }, [news, selectedUrl]);

  const selected = useMemo(
    () => news.find((item) => item.url === selectedUrl) ?? news[0],
    [news, selectedUrl]
  );

  if (!selected) {
    return <EmptyState icon={<Globe2 size={24} />} text="Belum ada threat feed." />;
  }

  return (
    <section className="feed-layout">
      <Panel className="feed-list-panel" title="Latest Threat News" icon={<Globe2 size={18} />}>
        <div className="feed-items">
          {news.map((item) => (
            <button
              className={item.url === selected.url ? "selected" : ""}
              key={item.url}
              onClick={() => setSelectedUrl(item.url)}
              type="button"
            >
              <strong>{item.title}</strong>
              <span>{item.source} - {formatApiDate(item.published_at)}</span>
            </button>
          ))}
        </div>
      </Panel>

      <Panel className="feed-preview-panel" title="Web Overview" icon={<Globe2 size={18} />}>
        <div className="web-overview">
          <div className="website-bar">
            <Globe2 size={16} />
            <span>{hostname(selected.url)}</span>
          </div>
          <div className="overview-content">
            <span className="source-label">{selected.source}</span>
            <h2>{selected.title}</h2>
            <div className="overview-date">
              <CalendarDays size={15} />
              {formatApiDateTime(selected.published_at, { dateStyle: "long", timeStyle: "short" })}
            </div>
            <p>{selected.summary || "Summary belum tersedia untuk artikel ini."}</p>
            <a href={selected.url} rel="noreferrer" target="_blank">
              <ExternalLink size={17} />
              Buka website
            </a>
          </div>
        </div>
      </Panel>
    </section>
  );
}
