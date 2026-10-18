"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { fetchIncidentDossier } from "@/lib/api/services/incidents";
import { FileText, Download, Copy, Check, FileCheck2, Loader2 } from "lucide-react";
import { toast } from "sonner";

interface DossierModalProps {
  incidentId: string;
}

export function DossierModal({ incidentId }: DossierModalProps) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [dossierContent, setDossierContent] = useState<string | null>(null);
  const [filename, setFilename] = useState(`SOC_Dossier_${incidentId}.md`);
  const [copied, setCopied] = useState(false);

  const handleOpen = async () => {
    setOpen(true);
    if (!dossierContent) {
      setLoading(true);
      try {
        const res = await fetchIncidentDossier(incidentId);
        setDossierContent(res.content);
        if (res.filename) setFilename(res.filename);
      } catch {
        toast.error("Failed to generate dossier report.");
        setDossierContent("# Forensic Investigation Dossier\n\nError generating report.");
      } finally {
        setLoading(false);
      }
    }
  };

  const handleDownload = () => {
    if (!dossierContent) return;
    const blob = new Blob([dossierContent], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    toast.success(`Downloaded ${filename}`);
  };

  const handleCopy = () => {
    if (!dossierContent) return;
    navigator.clipboard.writeText(dossierContent);
    setCopied(true);
    toast.success("Dossier copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        onClick={handleOpen}
        className="gap-1.5 text-xs border-primary/30 text-primary hover:bg-primary/10"
      >
        <FileText className="size-3.5" />
        SOC Dossier Report
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col p-6">
          <DialogHeader className="pb-3 border-b">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCheck2 className="size-5 text-emerald-600 dark:text-emerald-400" />
                <div>
                  <DialogTitle className="text-base font-semibold">
                    Cryptographic Forensic Investigation Dossier
                  </DialogTitle>
                  <DialogDescription className="text-xs">
                    Authoritative, auditable incident package with SHA-256 integrity hash & chain of custody.
                  </DialogDescription>
                </div>
              </div>
            </div>
          </DialogHeader>

          <div className="flex items-center justify-between py-2 border-b text-xs">
            <span className="font-mono text-muted-foreground text-[11px] truncate max-w-sm">
              {filename}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleCopy}
                disabled={loading || !dossierContent}
                className="gap-1 text-xs h-7"
              >
                {copied ? <Check className="size-3 text-emerald-500" /> : <Copy className="size-3" />}
                {copied ? "Copied" : "Copy Raw"}
              </Button>
              <Button
                size="sm"
                onClick={handleDownload}
                disabled={loading || !dossierContent}
                className="gap-1 text-xs h-7"
              >
                <Download className="size-3" />
                Download .MD
              </Button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto mt-2 rounded-md bg-muted/40 p-4 font-mono text-xs border border-border">
            {loading ? (
              <div className="flex flex-col items-center justify-center py-12 gap-2 text-muted-foreground">
                <Loader2 className="size-6 animate-spin text-primary" />
                <span>Compiling evidence bundle & computing cryptographic hash...</span>
              </div>
            ) : (
              <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-foreground select-text">
                {dossierContent}
              </pre>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
