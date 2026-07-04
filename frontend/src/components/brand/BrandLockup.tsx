type Props = {
  compact?: boolean;
  inverse?: boolean;
};

export function BrandLockup({ compact = false, inverse = false }: Props) {
  return (
    <div className={`brand-lockup${compact ? " compact" : ""}${inverse ? " inverse" : ""}`}>
      <img alt="" aria-hidden="true" src="/brand/threatlens-mark.png" />
      {!compact && (
        <div className="brand-wordmark">
          <strong><span>Threat</span><span>Lens</span></strong>
          <small>Open Source Threat Intelligence Platform</small>
        </div>
      )}
    </div>
  );
}
