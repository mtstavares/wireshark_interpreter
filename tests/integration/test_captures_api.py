from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.analyzers.command import Analyzer, AnalyzerResult
from backend.app.core.config import Settings
from backend.app.domain.analyses import AnalyzerStatus, Artifact
from backend.app.main import create_app


class SuccessfulAnalyzer:
    name = "test-analyzer"

    def analyze(
        self, capture_path: Path, output_dir: Path, timeout_seconds: int
    ) -> AnalyzerResult:
        assert capture_path.is_file()
        assert timeout_seconds > 0
        output_dir.mkdir(parents=True)
        artifact_path = output_dir / "events.json"
        artifact_path.write_text('{"event":"ok"}\n', encoding="utf-8")
        return AnalyzerResult(
            status=AnalyzerStatus.COMPLETED,
            version="test-analyzer 1.0",
            duration_ms=1,
            exit_code=0,
            diagnostic=None,
            artifacts=[Artifact(path="events.json", size_bytes=artifact_path.stat().st_size)],
        )


class SyntheticZeekAnalyzer:
    name = "zeek"

    def analyze(
        self, capture_path: Path, output_dir: Path, timeout_seconds: int
    ) -> AnalyzerResult:
        del capture_path, timeout_seconds
        output_dir.mkdir(parents=True)
        conn_path = output_dir / "conn.log"
        dns_path = output_dir / "dns.log"
        conn_path.write_text(
            '{"ts":1700000000.0,"uid":"C1","id.orig_h":"10.0.0.5",'
            '"id.orig_p":51000,"id.resp_h":"8.8.8.8","id.resp_p":53,'
            '"proto":"udp","service":"dns","duration":0.2,'
            '"orig_bytes":40,"resp_bytes":80,"orig_pkts":1,"resp_pkts":1}\n',
            encoding="utf-8",
        )
        dns_path.write_text(
            '{"ts":1700000000.01,"uid":"C1","id.orig_h":"10.0.0.5",'
            '"id.resp_h":"8.8.8.8","query":"example.com"}\n',
            encoding="utf-8",
        )
        return AnalyzerResult(
            status=AnalyzerStatus.COMPLETED,
            version="zeek test",
            duration_ms=1,
            exit_code=0,
            diagnostic=None,
            artifacts=[
                Artifact(path="conn.log", size_bytes=conn_path.stat().st_size),
                Artifact(path="dns.log", size_bytes=dns_path.stat().st_size),
            ],
        )


class SyntheticFindingAnalyzer:
    name = "zeek"

    def analyze(
        self, capture_path: Path, output_dir: Path, timeout_seconds: int
    ) -> AnalyzerResult:
        del capture_path, timeout_seconds
        output_dir.mkdir(parents=True)
        conn_path = output_dir / "conn.log"
        rows = [
            (
                f'{{"ts":1700000000.{index},"uid":"C{index}",'
                '"id.orig_h":"10.0.0.5","id.orig_p":51000,'
                f'"id.resp_h":"10.0.1.{index}","id.resp_p":445,'
                '"proto":"tcp","duration":0.01,"orig_pkts":1}'
            )
            for index in range(1, 11)
        ]
        conn_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        return AnalyzerResult(
            status=AnalyzerStatus.COMPLETED,
            version="zeek test",
            duration_ms=1,
            exit_code=0,
            diagnostic=None,
            artifacts=[Artifact(path="conn.log", size_bytes=conn_path.stat().st_size)],
        )


def _client(
    tmp_path: Path,
    max_upload_bytes: int = 1024,
    analyzers: list[Analyzer] | None = None,
    asset_context_path: Path | None = None,
    reputation_path: Path | None = None,
) -> TestClient:
    app = create_app(
        Settings(
            data_dir=tmp_path,
            max_upload_bytes=max_upload_bytes,
            asset_context_path=asset_context_path,
            reputation_path=reputation_path,
        ),
        analyzers=analyzers,
    )
    return TestClient(app)


def test_upload_and_get_valid_pcap(tmp_path: Path) -> None:
    content = bytes.fromhex("d4c3b2a1") + b"test-payload"

    with _client(tmp_path) as client:
        response = client.post(
            "/api/v1/captures",
            files={"file": ("sample.pcap", content, "application/vnd.tcpdump.pcap")},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["capture_format"] == "pcap"
        assert body["size_bytes"] == len(content)
        assert len(body["sha256"]) == 64

        get_response = client.get(f"/api/v1/captures/{body['id']}")
        assert get_response.status_code == 200
        assert get_response.json() == body

    stored_files = list((tmp_path / "captures").glob("*.pcap"))
    assert len(stored_files) == 1
    assert stored_files[0].read_bytes() == content


def test_health_list_and_not_found(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/api/v1/captures").json() == []
        assert client.get("/api/v1/captures/missing").status_code == 404


def test_restart_marks_an_unfinished_analysis_as_failed(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, max_upload_bytes=1024)
    first_app = create_app(settings, analyzers=[SuccessfulAnalyzer()])
    with TestClient(first_app) as client:
        upload = client.post(
            "/api/v1/captures",
            files={
                "file": (
                    "sample.pcap",
                    bytes.fromhex("d4c3b2a1") + b"test-payload",
                    "application/octet-stream",
                )
            },
        )
        capture_id = upload.json()["id"]
        analysis = client.app.state.analysis_service.create(capture_id)
        assert analysis.status.value == "queued"

    restarted_app = create_app(settings, analyzers=[SuccessfulAnalyzer()])
    with TestClient(restarted_app) as client:
        response = client.get(f"/api/v1/analyses/{analysis.id}")
        assert response.status_code == 200
        assert response.json()["status"] == "failed"
        assert "application restart" in response.json()["error_message"]


def test_rejects_invalid_signature_without_residue(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        response = client.post(
            "/api/v1/captures",
            files={"file": ("fake.pcap", b"not really a capture", "application/octet-stream")},
        )

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    assert list((tmp_path / "captures").iterdir()) == []


def test_rejects_oversized_capture_without_residue(tmp_path: Path) -> None:
    content = bytes.fromhex("d4c3b2a1") + b"x" * 20

    with _client(tmp_path, max_upload_bytes=10) as client:
        response = client.post(
            "/api/v1/captures",
            files={"file": ("large.pcap", content, "application/octet-stream")},
        )

    assert response.status_code == 413
    assert list((tmp_path / "captures").iterdir()) == []


def test_create_and_query_completed_analysis(tmp_path: Path) -> None:
    content = bytes.fromhex("d4c3b2a1") + b"test-payload"

    with _client(tmp_path, analyzers=[SuccessfulAnalyzer()]) as client:
        upload_response = client.post(
            "/api/v1/captures",
            files={"file": ("sample.pcap", content, "application/octet-stream")},
        )
        capture_id = upload_response.json()["id"]

        create_response = client.post(f"/api/v1/captures/{capture_id}/analyses")
        assert create_response.status_code == 202
        analysis_id = create_response.json()["id"]

        get_response = client.get(f"/api/v1/analyses/{analysis_id}")
        assert get_response.status_code == 200
        analysis = get_response.json()
        assert analysis["status"] == "completed"
        assert analysis["analyzer_runs"][0]["status"] == "completed"
        assert analysis["analyzer_runs"][0]["artifacts"][0]["path"] == "events.json"

        list_response = client.get(f"/api/v1/captures/{capture_id}/analyses")
        assert list_response.status_code == 200
        assert [item["id"] for item in list_response.json()] == [analysis_id]


def test_analysis_endpoints_return_not_found(tmp_path: Path) -> None:
    with _client(tmp_path, analyzers=[SuccessfulAnalyzer()]) as client:
        assert client.post("/api/v1/captures/missing/analyses").status_code == 404
        assert client.get("/api/v1/captures/missing/analyses").status_code == 404
        assert client.get("/api/v1/analyses/missing").status_code == 404
        assert client.get("/api/v1/analyses/missing/report").status_code == 404
        assert client.get("/api/v1/analyses/missing/report.html").status_code == 404


def test_normalized_flows_events_and_inventory(tmp_path: Path) -> None:
    content = bytes.fromhex("d4c3b2a1") + b"test-payload"

    with _client(tmp_path, analyzers=[SyntheticZeekAnalyzer()]) as client:
        upload = client.post(
            "/api/v1/captures",
            files={"file": ("sample.pcap", content, "application/octet-stream")},
        ).json()
        created = client.post(f"/api/v1/captures/{upload['id']}/analyses").json()
        analysis_id = created["id"]

        analysis = client.get(f"/api/v1/analyses/{analysis_id}").json()
        flows = client.get(f"/api/v1/analyses/{analysis_id}/flows").json()
        events = client.get(f"/api/v1/analyses/{analysis_id}/events").json()
        inventory = client.get(f"/api/v1/analyses/{analysis_id}/inventory").json()

        assert analysis["normalization"]["status"] == "completed"
        assert analysis["normalization"]["flow_count"] == 1
        assert analysis["normalization"]["event_count"] == 1
        assert flows[0]["application"] == "dns"
        assert events[0]["details"]["query"] == "example.com"
        assert {host["ip"] for host in inventory["hosts"]} == {"10.0.0.5", "8.8.8.8"}
        assert inventory["services"][0]["port"] == 53


def test_detection_status_and_findings_endpoints(tmp_path: Path) -> None:
    content = bytes.fromhex("d4c3b2a1") + b"test-payload"
    asset_context = tmp_path / "assets.json"
    asset_context.write_text(
        '{"allowlist":["10.0.0.0/8"],"assets":{"10.0.0.5":'
        '{"name":"scanner-lab","role":"test-client","owner":"security"}}}',
        encoding="utf-8",
    )
    reputation = tmp_path / "reputation.json"
    reputation.write_text(
        '{"provider":"test-intel","indicators":{"10.0.1.1":'
        '{"verdict":"suspicious","confidence":0.8,"description":"fixture local"}}}',
        encoding="utf-8",
    )

    with _client(
        tmp_path,
        analyzers=[SyntheticFindingAnalyzer()],
        asset_context_path=asset_context,
        reputation_path=reputation,
    ) as client:
        upload = client.post(
            "/api/v1/captures",
            files={"file": ("sample.pcap", content, "application/octet-stream")},
        ).json()
        created = client.post(f"/api/v1/captures/{upload['id']}/analyses").json()
        analysis_id = created["id"]

        analysis = client.get(f"/api/v1/analyses/{analysis_id}").json()
        response = client.get(f"/api/v1/analyses/{analysis_id}/findings")
        filtered = client.get(
            f"/api/v1/analyses/{analysis_id}/findings",
            params={"severity": "medium", "category": "network-service-scanning"},
        )

        assert analysis["detection"]["status"] == "completed"
        assert analysis["detection"]["finding_count"] == 1
        assert response.status_code == 200
        assert len(response.json()) == 1
        finding = response.json()[0]
        assert finding["destination_port"] == 445
        assert len(finding["evidence"]) == 10
        assert filtered.json() == [finding]
        assert client.get(f"/api/v1/findings/{finding['id']}").json() == finding
        assert client.get("/api/v1/findings/missing").status_code == 404

        enrichments = client.get(
            f"/api/v1/analyses/{analysis_id}/enrichments"
        ).json()
        assets = client.get(f"/api/v1/analyses/{analysis_id}/assets").json()
        assert {(item["namespace"], item["value"]) for item in enrichments} == {
            ("MITRE ATT&CK", "T1046"),
            ("reputation", "suspicious"),
        }
        assert all(item["influence"] == "context_only" for item in enrichments)
        scanner = next(item for item in assets if item["ip"] == "10.0.0.5")
        assert scanner["name"] == "scanner-lab"
        assert scanner["allowlisted"] is True
        assert scanner["provenance"] == "asset-context-file"

        report_response = client.get(f"/api/v1/analyses/{analysis_id}/report")
        repeated_report = client.get(f"/api/v1/analyses/{analysis_id}/report")
        html_response = client.get(f"/api/v1/analyses/{analysis_id}/report.html")
        report = report_response.json()

        assert report_response.status_code == 200
        assert "report.json" in report_response.headers["content-disposition"]
        assert report == repeated_report.json()
        assert report["schema_version"] == "1.2"
        assert len(report["activities"]) == 1
        assert report["activities"][0]["statement"].startswith(
            "O IP 10.0.0.5 realizou uma possivel varredura"
        )
        assert report["activities"][0]["evidence_refs"]
        assert "enrichments" in report
        assert "assets" in report
        assert report["capture"]["original_filename"] == "sample.pcap"
        assert report["summary"]["finding_count"] == 1
        assert report["summary"]["enrichment_count"] == 2
        assert len(report["assets"]) == 11
        assert report["summary"]["host_count"] == 11
        assert report["findings"][0]["wireshark_filter"] == (
            "ip.src == 10.0.0.5 && (tcp.dstport == 445 || udp.dstport == 445)"
        )
        assert {item["value"] for item in report["indicators"]} == {"10.0.0.5", "T1046"}
        assert html_response.status_code == 200
        assert html_response.headers["content-type"].startswith("text/html")
        assert "report.html" in html_response.headers["content-disposition"]
        assert "Relatório de segurança" in html_response.text
        assert "tcp.dstport == 445" in html_response.text
        assert "Enriquecimento e provenance" in html_response.text
        assert "O que aconteceu" in html_response.text

        repeated = client.post(f"/api/v1/captures/{upload['id']}/analyses").json()
        cached = client.get(
            f"/api/v1/analyses/{repeated['id']}/enrichments"
        ).json()
        reputation_item = next(item for item in cached if item["kind"] == "reputation")
        assert reputation_item["cache_hit"] is True
