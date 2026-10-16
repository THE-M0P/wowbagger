export const SIGNUP_URL = "#local-only";
export const DEMO_URL = "#local-only";
export const PRICING_URL = "#local-only";

export function ctaUrl(_base: string, _slug: string): string {
  return "#local-only";
}

export function track(_event: string, _props: Record<string, string | undefined> = {}): void {
  return;
}

export function trackCta(_cta: string, _surface?: string): void {
  return;
}
