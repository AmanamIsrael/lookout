import { ShieldCheck } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { ActorClass, RiskBand } from "../api";
import { bandLabel, classLabel, classMeaning, riskBand } from "../lib/format";

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

const buttonStyles: Record<ButtonVariant, string> = {
  primary: "bg-accent text-on-accent shadow-card hover:bg-accent/90",
  secondary: "bg-raised text-ink ring-1 ring-line-strong shadow-card hover:bg-hover",
  ghost: "text-ink-2 hover:bg-hover hover:text-ink",
  danger: "bg-critical text-white shadow-card hover:bg-critical/90",
};

export function Button({
  variant = "secondary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      type="button"
      className={`inline-flex h-8 items-center justify-center gap-1.5 rounded-md px-3 text-sm font-medium whitespace-nowrap transition-colors disabled:pointer-events-none disabled:opacity-50 ${buttonStyles[variant]} ${className}`}
      {...props}
    />
  );
}

export const bandFill: Record<RiskBand, string> = {
  hostile: "bg-critical",
  suspicious: "bg-serious",
  watch: "bg-warning",
  benign: "bg-good",
};

/** A thin bar filled to risk/100 in its band's color. */
export function RiskMeter({ risk, className = "" }: { risk: number; className?: string }) {
  return (
    <span className={`block h-1 overflow-hidden rounded-full bg-line ${className}`} aria-hidden>
      <span
        className={`block h-full rounded-full ${bandFill[riskBand(risk)]}`}
        style={{ width: `${Math.max(4, risk)}%` }}
      />
    </span>
  );
}

/** Risk score, its band name and a meter: the color is never the only cue. */
export function RiskScore({ risk, size = "sm" }: { risk: number; size?: "sm" | "lg" }) {
  const band = riskBand(risk);
  if (size === "lg") {
    return (
      <div className="w-36" title={`Risk ${risk} of 100`}>
        <div className="flex items-baseline gap-1.5">
          <span className="text-3xl font-semibold tabular-nums">{risk}</span>
          <span className="text-sm font-medium text-ink-2">{bandLabel[band]}</span>
        </div>
        <RiskMeter risk={risk} className="mt-1.5 h-1.5" />
      </div>
    );
  }
  return (
    <div className="w-14 shrink-0" title={`Risk ${risk} of 100`}>
      <div className="text-lg leading-6 font-semibold tabular-nums">{risk}</div>
      <RiskMeter risk={risk} className="mt-0.5" />
      <div className="mt-1 text-[11px] leading-none text-muted">{bandLabel[band]}</div>
    </div>
  );
}

/** Inline risk for sentences and tight rows: dot, score and band name. */
export function RiskBadge({ risk }: { risk: number }) {
  const band = riskBand(risk);
  return (
    <span className="inline-flex items-center gap-1.5 text-xs" title={`Risk ${risk} of 100`}>
      <span className={`size-2 rounded-full ${bandFill[band]}`} aria-hidden />
      <span className="font-semibold tabular-nums">{risk}</span>
      <span className="text-ink-2">{bandLabel[band]}</span>
    </span>
  );
}

export function ClassBadge({ value }: { value: ActorClass }) {
  return (
    <span
      className="inline-flex items-center rounded bg-sunken px-1.5 py-0.5 text-xs font-medium text-ink-2 ring-1 ring-line"
      title={classMeaning[value]}
    >
      {classLabel[value]}
    </span>
  );
}

export function VerifiedBadge({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-success-text" title={label}>
      <ShieldCheck className="size-3.5" aria-hidden />
      Verified
    </span>
  );
}

export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium text-ink-2 ring-1 ring-line">
      {children}
    </span>
  );
}

export function Card({
  title,
  hint,
  action,
  children,
  className = "",
}: {
  title?: ReactNode;
  hint?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-xl bg-surface shadow-card ring-1 ring-line ${className}`}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 px-4 pt-3.5 pb-2.5">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold">{title}</h2>
            {hint && <p className="mt-0.5 text-xs text-muted">{hint}</p>}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="px-6 py-10 text-center">
      <p className="text-sm font-medium">{title}</p>
      {children && <div className="mx-auto mt-1 max-w-md text-sm text-ink-2">{children}</div>}
    </div>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: string; count?: number }[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <fieldset
      aria-label={label}
      className="inline-flex max-w-full overflow-x-auto rounded-lg bg-sunken p-0.5 ring-1 ring-line"
    >
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
          className={`inline-flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium whitespace-nowrap transition-colors ${
            value === o.value
              ? "bg-raised text-ink shadow-card ring-1 ring-line"
              : "text-ink-2 hover:text-ink"
          }`}
        >
          {o.label}
          {o.count !== undefined && <span className="text-muted tabular-nums">{o.count}</span>}
        </button>
      ))}
    </fieldset>
  );
}

export function ErrorText({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <p role="alert" className="text-sm text-critical-text">
      {error instanceof Error ? error.message : "Something went wrong"}
    </p>
  );
}
