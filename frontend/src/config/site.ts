export const siteConfig = {
  name: "XAI-IDPS",
  fullName: "Explainable Hybrid Intrusion Detection & Prevention System",
  description:
    "Local-first academic security analyst dashboard with hybrid detection, deterministic risk scoring, detection-rule provenance, and evidence-grounded local explanations.",
  version: "1.0.0-foundation",
  author: "XAI-IDPS Development Team",
  links: {
    docs: "/docs",
  },
} as const;

export type SiteConfig = typeof siteConfig;
