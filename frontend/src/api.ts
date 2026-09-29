import type {
  Analysis,
  AssetContext,
  Capture,
  Enrichment,
  Finding,
  Flow,
  Inventory,
  NetworkEvent,
  RecentAnalysis,
  SecurityReport,
} from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    let message = `Falha HTTP ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: string };
      message = body.detail ?? message;
    } catch {
      // A resposta pode não ser JSON.
    }
    throw new ApiError(message, response.status);
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => request<{ status: string }>("/healthz"),
  captures: () => request<Capture[]>("/api/v1/captures?limit=50"),
  capture: (id: string) => request<Capture>(`/api/v1/captures/${id}`),
  analysesForCapture: (captureId: string) =>
    request<Analysis[]>(`/api/v1/captures/${captureId}/analyses?limit=20`),
  analysis: (id: string) => request<Analysis>(`/api/v1/analyses/${id}`),
  createAnalysis: (captureId: string) =>
    request<Analysis>(`/api/v1/captures/${captureId}/analyses`, { method: "POST" }),
  findings: (id: string) =>
    request<Finding[]>(`/api/v1/analyses/${id}/findings?limit=1000`),
  inventory: (id: string) => request<Inventory>(`/api/v1/analyses/${id}/inventory`),
  flows: (id: string) => request<Flow[]>(`/api/v1/analyses/${id}/flows?limit=1000`),
  events: (id: string) =>
    request<NetworkEvent[]>(`/api/v1/analyses/${id}/events?limit=1000`),
  enrichments: (id: string) =>
    request<Enrichment[]>(`/api/v1/analyses/${id}/enrichments`),
  assets: (id: string) => request<AssetContext[]>(`/api/v1/analyses/${id}/assets`),
  report: (id: string) => request<SecurityReport>(`/api/v1/analyses/${id}/report`),
};

export async function dashboardData(): Promise<{
  captures: Capture[];
  analyses: RecentAnalysis[];
}> {
  const captures = await api.captures();
  const groups = await Promise.all(
    captures.slice(0, 12).map(async (capture) => {
      const analyses = await api.analysesForCapture(capture.id);
      return analyses.map((analysis) => ({
        ...analysis,
        capture_name: capture.original_filename,
      }));
    }),
  );
  return {
    captures,
    analyses: groups.flat().sort((left, right) =>
      right.created_at.localeCompare(left.created_at),
    ),
  };
}

export function uploadCapture(
  file: File,
  onProgress: (percentage: number) => void,
): Promise<Capture> {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append("file", file);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/captures");
    xhr.responseType = "json";
    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      }
    });
    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.response as Capture);
        return;
      }
      const body = xhr.response as { detail?: string } | null;
      reject(new ApiError(body?.detail ?? `Falha HTTP ${xhr.status}`, xhr.status));
    });
    xhr.addEventListener("error", () => reject(new Error("Falha de rede durante o upload")));
    xhr.send(form);
  });
}
