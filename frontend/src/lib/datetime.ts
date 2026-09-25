const TIMEZONE_OFFSET_PATTERN = /(?:Z|[+-]\d{2}:?\d{2})$/i;

export function parseApiDate(value: string): Date {
  return new Date(TIMEZONE_OFFSET_PATTERN.test(value) ? value : `${value}Z`);
}

export function formatApiDate(value: string, options?: Intl.DateTimeFormatOptions): string {
  return parseApiDate(value).toLocaleDateString("id-ID", options);
}

export function formatApiDateTime(value: string, options?: Intl.DateTimeFormatOptions): string {
  return parseApiDate(value).toLocaleString("id-ID", options);
}
