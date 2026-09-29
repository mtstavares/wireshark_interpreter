import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, type DragEvent, useRef, useState } from "react";
import { useNavigate } from "react-router";

import { api, uploadCapture } from "../api";
import { PageHeader } from "../components";
import { formatBytes } from "../utils";

const MAX_SIZE = 100 * 1024 * 1024;

export function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState(0);
  const [validationError, setValidationError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: async (selected: File) => {
      const capture = await uploadCapture(selected, setProgress);
      return api.createAnalysis(capture.id);
    },
    onSuccess: async (analysis) => {
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      navigate(`/analyses/${analysis.id}`);
    },
  });

  const selectFile = (candidate: File | undefined) => {
    setValidationError(null);
    setProgress(0);
    if (!candidate) return;
    if (!candidate.name.toLowerCase().match(/\.pcap(ng)?$/)) {
      setValidationError("Selecione um arquivo com extensão .pcap ou .pcapng.");
      setFile(null);
      return;
    }
    if (candidate.size > MAX_SIZE) {
      setValidationError("O arquivo excede o limite de 100 MB deste ambiente.");
      setFile(null);
      return;
    }
    setFile(candidate);
  };

  const onInput = (event: ChangeEvent<HTMLInputElement>) => selectFile(event.target.files?.[0]);
  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    selectFile(event.dataTransfer.files[0]);
  };

  return (
    <>
      <PageHeader
        eyebrow="Ingestão segura"
        title="Nova análise"
        description="Envie uma captura para validação, extração e detecção offline."
      />
      <section className="upload-layout">
        <div className="panel upload-panel">
          <div
            className={`dropzone ${file ? "dropzone-ready" : ""}`}
            onDragOver={(event) => event.preventDefault()}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(event) => event.key === "Enter" && inputRef.current?.click()}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".pcap,.pcapng"
              onChange={onInput}
              hidden
            />
            <span className="upload-icon" aria-hidden="true">⇧</span>
            <h2>{file ? file.name : "Arraste sua captura aqui"}</h2>
            <p>{file ? `${formatBytes(file.size)} · pronta para envio` : "ou clique para selecionar .pcap ou .pcapng"}</p>
          </div>
          {(mutation.isPending || progress > 0) && (
            <div className="progress-block">
              <div><span>Upload e criação da análise</span><strong>{progress}%</strong></div>
              <progress max="100" value={progress} />
            </div>
          )}
          {(validationError || mutation.error) && (
            <div className="callout callout-danger" role="alert">
              {validationError ?? mutation.error?.message}
            </div>
          )}
          <div className="form-actions">
            <button
              className="button button-primary"
              disabled={!file || mutation.isPending}
              onClick={() => file && mutation.mutate(file)}
            >
              {mutation.isPending ? "Enviando…" : "Enviar e analisar"}
            </button>
            {file && !mutation.isPending && (
              <button className="button button-ghost" onClick={() => setFile(null)}>Remover</button>
            )}
          </div>
        </div>
        <aside className="panel guidance-panel">
          <p className="eyebrow">O que acontece</p>
          <ol className="numbered-list">
            <li><strong>Validação</strong><span>Assinatura, formato, tamanho e SHA-256.</span></li>
            <li><strong>Extração</strong><span>Zeek, Suricata e TShark disponíveis.</span></li>
            <li><strong>Detecção</strong><span>Regras reproduzíveis com evidências.</span></li>
            <li><strong>Relatório</strong><span>JSON e HTML sem dependência de LLM.</span></li>
          </ol>
          <div className="callout"><strong>Privacidade</strong><span>A análise base é local e offline.</span></div>
        </aside>
      </section>
    </>
  );
}
