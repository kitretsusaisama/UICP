export function OtpTimer({ seconds = 30 }: { seconds?: number }) {
  return <span className="text-sm text-muted">{seconds}s</span>;
}
