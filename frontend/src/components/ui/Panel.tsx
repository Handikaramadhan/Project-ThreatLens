import type React from "react";

type Props = {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  wide?: boolean;
  className?: string;
  action?: React.ReactNode;
};

export function Panel({ title, icon, children, wide = false, className = "", action }: Props) {
  const classes = ["panel", wide ? "panel-wide" : "", className].filter(Boolean).join(" ");
  return (
    <article className={classes}>
      <header><div>{icon}<h2>{title}</h2></div>{action}</header>
      {children}
    </article>
  );
}
