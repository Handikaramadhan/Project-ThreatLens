type Props = {
  compact?: boolean;
  inverse?: boolean;
};

export function BrandLockup({ compact = false, inverse = false }: Props) {
  return (
    <div className={`brand-lockup${compact ? " compact" : ""}${inverse ? " inverse" : ""}`}>
      <img alt="" aria-hidden="true" height={40} src="/brand/threatlens-mark.png" width={40} />
      {!compact && (
        <div className="brand-wordmark">
          <strong><span>Threat</span><span>Lens</span></strong>
          <small>Open Source Threat Intelligence Platform</small>
        </div>
      )}
    </div>
  );
}
