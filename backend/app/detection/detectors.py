from __future__ import annotations

import json
import math
import statistics
from collections import defaultdict
from collections.abc import Callable, Hashable, Iterable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from ipaddress import ip_address, ip_network
from itertools import pairwise
from pathlib import Path
from typing import Any, ClassVar, Protocol, cast
from uuid import NAMESPACE_URL, uuid5

from backend.app.domain.findings import (
    AssertionStatus,
    DetectionContext,
    Finding,
    FindingEvidence,
    Severity,
)
from backend.app.domain.network import NetworkEvent, NetworkFlow

DETECTOR_VERSION = "1.1.0"
MAX_EVIDENCE = 25


class Detector(Protocol):
    name: str

    def detect(self, context: DetectionContext) -> list[Finding]: ...


@dataclass(frozen=True, slots=True)
class DetectorConfig:
    scan_window_seconds: int = 60
    vertical_scan_ports: int = 15
    horizontal_scan_hosts: int = 10
    brute_force_failures: int = 5
    password_spray_users: int = 5
    dns_suspicious_queries: int = 3
    beacon_min_connections: int = 5
    beacon_max_variation: float = 0.25


class PortScanDetector:
    name = "port-scan"

    def __init__(self, config: DetectorConfig) -> None:
        self._config = config

    def detect(self, context: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        vertical: dict[tuple[str, str], list[NetworkFlow]] = defaultdict(list)
        horizontal: dict[tuple[str, int, str], list[NetworkFlow]] = defaultdict(list)
        for flow in context.flows:
            if flow.dest_port is None:
                continue
            vertical[(flow.src_ip, flow.dest_ip)].append(flow)
            horizontal[(flow.src_ip, flow.dest_port, flow.transport)].append(flow)

        window = timedelta(seconds=self._config.scan_window_seconds)
        for (source_ip, destination_ip), flows in vertical.items():
            selected = _largest_window(flows, window, lambda flow: flow.dest_port)
            unique_ports = {flow.dest_port for flow in selected}
            if len(unique_ports) < self._config.vertical_scan_ports:
                continue
            severity = Severity.HIGH if len(unique_ports) >= 50 else Severity.MEDIUM
            findings.append(
                _finding(
                    context,
                    self.name,
                    key=f"vertical:{source_ip}:{destination_ip}",
                    title="Possível varredura vertical de portas",
                    category="network-service-scanning",
                    severity=severity,
                    confidence=_threshold_confidence(
                        len(unique_ports), self._config.vertical_scan_ports
                    ),
                    summary=(
                        f"O IP {source_ip} realizou uma possivel varredura de "
                        f"{len(unique_ports)} portas no IP {destination_ip} em uma janela de "
                        f"{self._config.scan_window_seconds} segundos."
                    ),
                    flows=selected,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=None,
                    mitigations=[
                        "Confirme se a origem é um scanner autorizado.",
                        "Restrinja serviços expostos e aplique rate limiting quando apropriado.",
                        "Correlacione com logs do firewall e dos serviços de destino.",
                    ],
                    mitre_attack=["T1046"],
                )
            )

        for (source_ip, destination_port, transport), flows in horizontal.items():
            selected = _largest_window(flows, window, lambda flow: flow.dest_ip)
            unique_hosts = {flow.dest_ip for flow in selected}
            if len(unique_hosts) < self._config.horizontal_scan_hosts:
                continue
            severity = Severity.HIGH if len(unique_hosts) >= 50 else Severity.MEDIUM
            findings.append(
                _finding(
                    context,
                    self.name,
                    key=f"horizontal:{source_ip}:{transport}:{destination_port}",
                    title="Possível varredura horizontal de hosts",
                    category="network-service-scanning",
                    severity=severity,
                    confidence=_threshold_confidence(
                        len(unique_hosts), self._config.horizontal_scan_hosts
                    ),
                    summary=(
                        f"O IP {source_ip} realizou uma possivel varredura de "
                        f"{len(unique_hosts)} hosts na porta {destination_port}/{transport} em "
                        f"uma janela de {self._config.scan_window_seconds} segundos."
                    ),
                    flows=selected,
                    source_ip=source_ip,
                    destination_ip=None,
                    destination_port=destination_port,
                    mitigations=[
                        "Valide se a origem executa descoberta ou monitoramento autorizado.",
                        "Revise regras de segmentação e bloqueie varreduras não autorizadas.",
                        "Investigue processos e credenciais usados pelo host de origem.",
                    ],
                    mitre_attack=["T1046"],
                )
            )
        return findings


class AuthenticationDetector:
    name = "authentication-abuse"

    def __init__(self, config: DetectorConfig) -> None:
        self._config = config

    def detect(self, context: DetectionContext) -> list[Finding]:
        failures = [event for event in context.events if _auth_outcome(event) == "failure"]
        successes = [event for event in context.events if _auth_outcome(event) == "success"]
        by_account: dict[tuple[str, str, str, str], list[NetworkEvent]] = defaultdict(list)
        by_target: dict[tuple[str, str, str], list[NetworkEvent]] = defaultdict(list)
        for event in failures:
            if event.src_ip is None or event.dest_ip is None:
                continue
            application = event.application or event.event_type
            username = _username(event) or "<unknown>"
            by_account[(event.src_ip, event.dest_ip, application, username)].append(event)
            by_target[(event.src_ip, event.dest_ip, application)].append(event)

        findings: list[Finding] = []
        for (source_ip, destination_ip, application, username), events in by_account.items():
            if len(events) < self._config.brute_force_failures:
                continue
            findings.append(
                _event_finding(
                    context,
                    self.name,
                    key=f"brute:{source_ip}:{destination_ip}:{application}:{username}",
                    title="Possível ataque de força bruta",
                    category="credential-access",
                    severity=Severity.HIGH,
                    confidence=_threshold_confidence(
                        len(events), self._config.brute_force_failures
                    ),
                    summary=(
                        f"O IP {source_ip} realizou {len(events)} tentativas de autenticação "
                        f"malsucedidas via {application.upper()} no IP {destination_ip}, "
                        f"usando o usuário {username}."
                    ),
                    events=events,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=events[0].dest_port,
                    mitigations=[
                        "Revise logs de autenticação do serviço e do endpoint.",
                        "Aplique MFA, rate limiting e bloqueio progressivo.",
                        "Investigue eventual sucesso após a sequência de falhas.",
                    ],
                    mitre_attack=["T1110"],
                )
            )

        for success in successes:
            if success.src_ip is None or success.dest_ip is None:
                continue
            application = success.application or success.event_type
            username = _username(success) or "<unknown>"
            key = (success.src_ip, success.dest_ip, application, username)
            preceding_failures = [
                event for event in by_account.get(key, []) if _occurred_before(event, success)
            ]
            if not preceding_failures:
                continue
            findings.append(
                _event_finding(
                    context,
                    self.name,
                    key=(
                        f"success-after-failure:{success.src_ip}:{success.dest_ip}:"
                        f"{application}:{username}"
                    ),
                    title="Autenticação bem-sucedida após falhas",
                    category="credential-access",
                    severity=Severity.HIGH,
                    confidence=min(0.98, 0.75 + len(preceding_failures) * 0.03),
                    summary=(
                        f"O IP {success.src_ip} teve sucesso ao autenticar via "
                        f"{application.upper()} no IP {success.dest_ip}, usando o usuário "
                        f"{username}, após {len(preceding_failures)} tentativa(s) malsucedida(s)."
                    ),
                    events=[*preceding_failures, success],
                    source_ip=success.src_ip,
                    destination_ip=success.dest_ip,
                    destination_port=success.dest_port,
                    mitigations=[
                        "Confirme com o proprietário da conta se o acesso foi legítimo.",
                        "Revogue sessões e redefina credenciais se houver suspeita de "
                        "comprometimento.",
                        "Correlacione o horário com MFA, endpoint e aplicação de destino.",
                    ],
                    mitre_attack=["T1110"],
                )
            )

        for (source_ip, destination_ip, application), events in by_target.items():
            users = {_username(event) for event in events if _username(event)}
            if len(users) < self._config.password_spray_users:
                continue
            findings.append(
                _event_finding(
                    context,
                    self.name,
                    key=f"spray:{source_ip}:{destination_ip}:{application}",
                    title="Possível password spraying",
                    category="credential-access",
                    severity=Severity.HIGH,
                    confidence=_threshold_confidence(len(users), self._config.password_spray_users),
                    summary=(
                        f"O IP {source_ip} tentou autenticar {len(users)} usuários diferentes "
                        f"via {application.upper()} no IP {destination_ip}, comportamento "
                        "compatível com password spraying."
                    ),
                    events=events,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=events[0].dest_port,
                    mitigations=[
                        "Aplique MFA e políticas contra tentativas distribuídas entre contas.",
                        "Bloqueie ou limite temporariamente a origem após validação.",
                        "Verifique contas que tiveram sucesso após as falhas.",
                    ],
                    mitre_attack=["T1110.003"],
                )
            )
        return findings


@dataclass(frozen=True, slots=True)
class CredentialAuthorizationRule:
    destination_ip: str
    service: str
    username: str
    source_networks: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CredentialAuthorizationPolicy:
    default: str = "unknown"
    rules: tuple[CredentialAuthorizationRule, ...] = ()

    @classmethod
    def load(cls, path: Path | None) -> CredentialAuthorizationPolicy:
        if path is None:
            return cls()
        raw_object = cast(object, json.loads(path.read_text(encoding="utf-8")))
        if not isinstance(raw_object, Mapping):
            raise ValueError("Credential policy must be a JSON object")
        raw = cast(Mapping[str, object], raw_object)
        default = str(raw.get("default", "unknown")).lower()
        if default not in {"unknown", "deny"}:
            raise ValueError("Credential policy default must be 'unknown' or 'deny'")
        parsed: list[CredentialAuthorizationRule] = []
        raw_rules = raw.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError("Credential policy rules must be a list")
        for item in cast(list[object], raw_rules):
            if not isinstance(item, Mapping):
                raise ValueError("Each credential policy rule must be an object")
            rule = cast(Mapping[str, object], item)
            networks = rule.get("source_networks", [])
            if not isinstance(networks, list):
                raise ValueError("source_networks must be a list")
            network_values = tuple(str(value) for value in cast(list[object], networks))
            for network in network_values:
                ip_network(network, strict=False)
            parsed.append(
                CredentialAuthorizationRule(
                    destination_ip=str(rule["destination_ip"]),
                    service=str(rule["service"]).lower(),
                    username=str(rule["username"]),
                    source_networks=network_values,
                )
            )
        return cls(default=default, rules=tuple(parsed))

    def decision(self, event: NetworkEvent, username: str | None) -> str:
        if username is None or event.dest_ip is None:
            return "unknown"
        candidates = [
            rule
            for rule in self.rules
            if rule.destination_ip == event.dest_ip
            and rule.service == (event.application or "").lower()
            and rule.username == username
        ]
        for rule in candidates:
            if not rule.source_networks:
                return "authorized"
            if event.src_ip and any(
                ip_address(event.src_ip) in ip_network(network, strict=False)
                for network in rule.source_networks
            ):
                return "authorized"
        return "unauthorized" if self.default == "deny" else "unknown"


class CleartextCredentialDetector:
    name = "cleartext-credential"

    def __init__(self, policy: CredentialAuthorizationPolicy | None = None) -> None:
        self._policy = policy or CredentialAuthorizationPolicy()

    def detect(self, context: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for event in context.events:
            if event.event_type != "authentication":
                continue
            username = _detail_text(event, "username")
            password = _detail_text(event, "password")
            outcome = _detail_text(event, "result") or "unknown"
            if username is None and password is None:
                continue
            authorization = self._policy.decision(event, username)
            unauthorized_success = outcome == "success" and authorization == "unauthorized"
            application = (event.application or "unknown").upper()
            credential = _credential_description(username, password)
            if outcome == "success":
                title = "Autenticação em texto claro bem-sucedida"
                statement = (
                    f"O IP {event.src_ip} autenticou com sucesso via {application} no IP "
                    f"{event.dest_ip}, usando {credential}."
                )
                assertion = AssertionStatus.OBSERVED
                confidence = 0.98
            elif outcome == "failure":
                title = "Tentativa de autenticação em texto claro malsucedida"
                statement = (
                    f"O IP {event.src_ip} tentou autenticar via {application} no IP "
                    f"{event.dest_ip}, usando {credential}, mas o serviço recusou a tentativa."
                )
                assertion = AssertionStatus.OBSERVED
                confidence = 0.98
            elif outcome == "possible":
                title = "Credencial HTTP observada em texto claro"
                status = _detail_text(event, "http_status") or "desconhecido"
                statement = (
                    f"O IP {event.src_ip} enviou via HTTP {credential} ao IP "
                    f"{event.dest_ip}, que respondeu com HTTP {status}; esse código isolado "
                    "não comprova sucesso do login."
                )
                assertion = AssertionStatus.INFERRED
                confidence = 0.80
            else:
                title = "Credencial observada em texto claro"
                statement = (
                    f"O IP {event.src_ip} enviou via {application} {credential} ao IP "
                    f"{event.dest_ip}; a captura não contém resposta conclusiva sobre o login."
                )
                assertion = AssertionStatus.OBSERVED
                confidence = 0.90
            if outcome == "success" and authorization == "authorized":
                statement += " O acesso corresponde à política local de autorização."
            elif unauthorized_success:
                title = "Autenticação não autorizada em texto claro"
                statement += " A origem ou conta não corresponde à política local de autorização."
            if password is not None:
                statement += (
                    " A senha trafegou sem criptografia e está reproduzida nesta evidência."
                )
            else:
                statement += " O identificador de conta trafegou sem criptografia."
            findings.append(
                _event_finding(
                    context,
                    self.name,
                    key=event.id,
                    title=title,
                    category="credential-access",
                    severity=Severity.CRITICAL if unauthorized_success else Severity.HIGH,
                    confidence=confidence,
                    assertion_status=assertion,
                    summary=statement,
                    events=[event],
                    source_ip=event.src_ip,
                    destination_ip=event.dest_ip,
                    destination_port=event.dest_port,
                    mitigations=[
                        "Desabilite o protocolo em texto claro e migre para uma "
                        "alternativa criptografada.",
                        "Redefina a credencial exposta e investigue sua reutilização "
                        "em outros sistemas.",
                        "Restrinja o acesso ao PCAP e aos relatórios, pois eles podem "
                        "conter a senha capturada.",
                    ],
                    mitre_attack=["T1040"],
                )
            )
        return findings


class CleartextProtocolDetector:
    name = "cleartext-protocol"

    _ports: ClassVar[dict[int, tuple[str, Severity]]] = {
        21: ("ftp", Severity.MEDIUM),
        23: ("telnet", Severity.HIGH),
        25: ("smtp", Severity.LOW),
        69: ("tftp", Severity.LOW),
        80: ("http", Severity.LOW),
        110: ("pop3", Severity.MEDIUM),
        143: ("imap", Severity.MEDIUM),
        389: ("ldap", Severity.MEDIUM),
        513: ("rlogin", Severity.HIGH),
    }

    def detect(self, context: DetectionContext) -> list[Finding]:
        grouped: dict[tuple[str, int, str], list[NetworkFlow]] = defaultdict(list)
        for flow in context.flows:
            if flow.dest_port in self._ports:
                service = self._ports[flow.dest_port][0]
                grouped[(flow.dest_ip, flow.dest_port, service)].append(flow)

        findings: list[Finding] = []
        for (destination_ip, destination_port, service), flows in grouped.items():
            severity = self._ports[destination_port][1]
            sources = {flow.src_ip for flow in flows}
            findings.append(
                _finding(
                    context,
                    self.name,
                    key=f"{destination_ip}:{destination_port}:{service}",
                    title=f"Uso observado de protocolo sem criptografia: {service.upper()}",
                    category="insecure-protocol",
                    severity=severity,
                    confidence=0.95,
                    assertion_status=AssertionStatus.OBSERVED,
                    summary=(
                        f"Foram observados {len(flows)} fluxo(s) de {len(sources)} origem(ns) "
                        f"para {destination_ip}:{destination_port}, associado a {service.upper()}. "
                        "O conteúdo pode ficar exposto quando o protocolo não usa "
                        "proteção adicional."
                    ),
                    flows=flows,
                    source_ip=next(iter(sources)) if len(sources) == 1 else None,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    mitigations=[
                        f"Substitua {service.upper()} por uma alternativa protegida "
                        "por TLS ou SSH.",
                        "Restrinja o serviço a redes e clientes estritamente necessários.",
                        "Verifique se credenciais ou dados sensíveis foram transmitidos.",
                    ],
                    mitre_attack=[],
                )
            )
        return findings


class DnsAnomalyDetector:
    name = "dns-anomaly"

    def __init__(self, config: DetectorConfig) -> None:
        self._config = config

    def detect(self, context: DetectionContext) -> list[Finding]:
        grouped: dict[str, list[tuple[NetworkEvent, str, float]]] = defaultdict(list)
        for event in context.events:
            query = _dns_query(event)
            if query is None or event.src_ip is None:
                continue
            entropy = _entropy(query.replace(".", ""))
            if len(query) >= 60 or entropy >= 4.0:
                grouped[event.src_ip].append((event, query, entropy))

        findings: list[Finding] = []
        for source_ip, suspicious in grouped.items():
            if len(suspicious) < self._config.dns_suspicious_queries and not any(
                len(query) >= 100 for _, query, _ in suspicious
            ):
                continue
            events = [item[0] for item in suspicious]
            max_length = max(len(item[1]) for item in suspicious)
            max_entropy = max(item[2] for item in suspicious)
            findings.append(
                _event_finding(
                    context,
                    self.name,
                    key=f"{source_ip}:dns",
                    title="Consultas DNS com possível codificação ou tunelamento",
                    category="command-and-control",
                    severity=Severity.MEDIUM,
                    confidence=min(0.95, 0.60 + len(suspicious) * 0.04),
                    summary=(
                        f"{source_ip} realizou {len(suspicious)} consultas DNS incomuns; "
                        f"o maior nome possui {max_length} caracteres e entropia {max_entropy:.2f}."
                    ),
                    events=events,
                    source_ip=source_ip,
                    destination_ip=None,
                    destination_port=53,
                    mitigations=[
                        "Compare os domínios com aplicações autorizadas e inventário do endpoint.",
                        "Inspecione volume, periodicidade e respostas DNS relacionadas.",
                        "Restrinja DNS direto e encaminhe consultas por resolvedores monitorados.",
                    ],
                    mitre_attack=["T1071.004"],
                )
            )
        return findings


class LegacySnmpDetector:
    name = "legacy-snmp"

    def detect(self, context: DetectionContext) -> list[Finding]:
        grouped: dict[tuple[str, str], list[NetworkEvent]] = defaultdict(list)
        for event in context.events:
            if event.dest_port != 161 or event.src_ip is None or event.dest_ip is None:
                continue
            version = _safe_int(event.details.get("snmp_version"))
            if version not in {0, 1}:
                continue
            grouped[(event.src_ip, event.dest_ip)].append(event)

        return [
            _event_finding(
                context,
                self.name,
                key=f"{source_ip}:{destination_ip}:161",
                title="Uso observado de versão legada do SNMP",
                category="insecure-protocol",
                severity=Severity.MEDIUM,
                confidence=0.99,
                assertion_status=AssertionStatus.OBSERVED,
                summary=(
                    f"Foram observadas {len(events)} requisição(ões) SNMPv1/v2c de "
                    f"{source_ip} para {destination_ip}. Essas versões não protegem o "
                    "conteúdo com criptografia."
                ),
                events=events,
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=161,
                mitigations=[
                    "Migre para SNMPv3 com autenticação e privacidade (authPriv).",
                    "Restrinja UDP/161 aos servidores de monitoramento autorizados.",
                    "Isole o gerenciamento em uma rede administrativa.",
                    "Troque as community strings após concluir a migração.",
                ],
                mitre_attack=[],
            )
            for (source_ip, destination_ip), events in grouped.items()
        ]


class BeaconingDetector:
    name = "beaconing"

    def __init__(self, config: DetectorConfig) -> None:
        self._config = config

    def detect(self, context: DetectionContext) -> list[Finding]:
        grouped: dict[tuple[str, str, int | None, str], list[NetworkFlow]] = defaultdict(list)
        for flow in context.flows:
            grouped[(flow.src_ip, flow.dest_ip, flow.dest_port, flow.transport)].append(flow)

        findings: list[Finding] = []
        for (source_ip, destination_ip, destination_port, transport), flows in grouped.items():
            if len(flows) < self._config.beacon_min_connections:
                continue
            ordered = sorted(flows, key=lambda flow: flow.start_time)
            intervals = [
                (right.start_time - left.start_time).total_seconds()
                for left, right in pairwise(ordered)
                if right.start_time > left.start_time
            ]
            if len(intervals) < self._config.beacon_min_connections - 1:
                continue
            mean_interval = statistics.mean(intervals)
            if mean_interval <= 0:
                continue
            variation = statistics.pstdev(intervals) / mean_interval
            if variation > self._config.beacon_max_variation:
                continue
            findings.append(
                _finding(
                    context,
                    self.name,
                    key=f"{source_ip}:{destination_ip}:{destination_port}:{transport}",
                    title="Comunicação periódica compatível com beaconing",
                    category="command-and-control",
                    severity=Severity.MEDIUM,
                    confidence=min(0.95, 0.70 + (1 - variation) * 0.20),
                    summary=(
                        f"Foram observadas {len(flows)} conexões de {source_ip} para "
                        f"{destination_ip}:{destination_port or 0}/{transport}, com "
                        "intervalo médio "
                        f"de {mean_interval:.1f}s e variação relativa de {variation:.2f}."
                    ),
                    flows=ordered,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    mitigations=[
                        "Identifique o processo responsável pelas conexões no endpoint.",
                        "Compare o destino com serviços autorizados, CDN e telemetria conhecida.",
                        "Bloqueie o destino somente após validar o contexto operacional.",
                    ],
                    mitre_attack=["T1071"],
                )
            )
        return findings


class SignatureAlertDetector:
    name = "suricata-signature"

    def detect(self, context: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for event in context.events:
            if event.source != "suricata" or event.event_type != "alert":
                continue
            alert = event.details.get("alert")
            if not isinstance(alert, Mapping):
                continue
            alert_data = cast(Mapping[str, Any], alert)
            signature = str(alert_data.get("signature", "Suricata alert"))
            numeric_severity = _safe_int(alert_data.get("severity")) or 3
            severity = {
                1: Severity.HIGH,
                2: Severity.MEDIUM,
                3: Severity.LOW,
            }.get(numeric_severity, Severity.LOW)
            findings.append(
                _event_finding(
                    context,
                    self.name,
                    key=f"{event.id}:{signature}",
                    title=signature[:160],
                    category="signature-alert",
                    severity=severity,
                    confidence=0.90,
                    assertion_status=AssertionStatus.SIGNATURE_MATCH,
                    summary=(
                        "O Suricata identificou tráfego correspondente a uma assinatura. "
                        "A correspondência precisa ser validada no contexto da sessão."
                    ),
                    events=[event],
                    source_ip=event.src_ip,
                    destination_ip=event.dest_ip,
                    destination_port=event.dest_port,
                    mitigations=[
                        "Revise a assinatura, os pacotes associados e o estado do destino.",
                        "Correlacione com logs do endpoint antes de confirmar o incidente.",
                    ],
                    mitre_attack=[],
                )
            )
        return findings


def default_detectors(
    config: DetectorConfig | None = None,
    credential_policy: CredentialAuthorizationPolicy | None = None,
) -> list[Detector]:
    detector_config = config or DetectorConfig()
    return [
        PortScanDetector(detector_config),
        AuthenticationDetector(detector_config),
        CleartextCredentialDetector(credential_policy),
        CleartextProtocolDetector(),
        LegacySnmpDetector(),
        DnsAnomalyDetector(detector_config),
        BeaconingDetector(detector_config),
        SignatureAlertDetector(),
    ]


def _finding(
    context: DetectionContext,
    detector_name: str,
    *,
    key: str,
    title: str,
    category: str,
    severity: Severity,
    confidence: float,
    summary: str,
    flows: list[NetworkFlow],
    source_ip: str | None,
    destination_ip: str | None,
    destination_port: int | None,
    mitigations: list[str],
    mitre_attack: list[str],
    assertion_status: AssertionStatus = AssertionStatus.INFERRED,
) -> Finding:
    return Finding(
        id=str(uuid5(NAMESPACE_URL, f"{context.analysis_id}:{detector_name}:{key}")),
        analysis_id=context.analysis_id,
        title=title,
        category=category,
        severity=severity,
        confidence=round(max(0.0, min(confidence, 1.0)), 3),
        assertion_status=assertion_status,
        summary=summary,
        first_seen=min((flow.start_time for flow in flows), default=None),
        last_seen=max((flow.end_time for flow in flows), default=None),
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        evidence=[
            FindingEvidence(kind="flow", reference=flow.id, source=",".join(flow.sources))
            for flow in flows[:MAX_EVIDENCE]
        ],
        mitigations=mitigations,
        mitre_attack=mitre_attack,
        detector_name=detector_name,
        detector_version=DETECTOR_VERSION,
    )


def _event_finding(
    context: DetectionContext,
    detector_name: str,
    *,
    key: str,
    title: str,
    category: str,
    severity: Severity,
    confidence: float,
    summary: str,
    events: list[NetworkEvent],
    source_ip: str | None,
    destination_ip: str | None,
    destination_port: int | None,
    mitigations: list[str],
    mitre_attack: list[str],
    assertion_status: AssertionStatus = AssertionStatus.INFERRED,
) -> Finding:
    timestamps = [event.occurred_at for event in events if event.occurred_at is not None]
    return Finding(
        id=str(uuid5(NAMESPACE_URL, f"{context.analysis_id}:{detector_name}:{key}")),
        analysis_id=context.analysis_id,
        title=title,
        category=category,
        severity=severity,
        confidence=round(max(0.0, min(confidence, 1.0)), 3),
        assertion_status=assertion_status,
        summary=summary,
        first_seen=min(timestamps, default=None),
        last_seen=max(timestamps, default=None),
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        evidence=[
            FindingEvidence(kind="event", reference=event.id, source=event.source)
            for event in events[:MAX_EVIDENCE]
        ],
        mitigations=mitigations,
        mitre_attack=mitre_attack,
        detector_name=detector_name,
        detector_version=DETECTOR_VERSION,
    )


def _largest_window(
    flows: list[NetworkFlow],
    window: timedelta,
    distinct_value: Callable[[NetworkFlow], Hashable],
) -> list[NetworkFlow]:
    ordered = sorted(flows, key=lambda flow: flow.start_time)
    best: list[NetworkFlow] = []
    left = 0
    for right, flow in enumerate(ordered):
        while flow.start_time - ordered[left].start_time > window:
            left += 1
        candidate = ordered[left : right + 1]
        if len({distinct_value(item) for item in candidate}) > len(
            {distinct_value(item) for item in best}
        ):
            best = candidate
    return best


def _threshold_confidence(value: int, threshold: int) -> float:
    return min(0.98, 0.70 + max(0, value - threshold) / max(threshold, 1) * 0.20)


def _flatten_details(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, Mapping):
        mapping = cast(Mapping[Any, Any], value)
        for key, item in mapping.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_details(item, child)
    else:
        yield prefix.lower(), value


def _auth_outcome(event: NetworkEvent) -> str | None:
    failure_terms = ("fail", "denied", "invalid", "unauthorized", "incorrect", "rejected")
    success_terms = ("success", "accepted", "authenticated", "logged in")
    for key, value in _flatten_details(event.details):
        if not any(token in key for token in ("status", "result", "success", "auth", "reply")):
            continue
        if isinstance(value, bool):
            return "success" if value else "failure"
        text = str(value).lower()
        if any(term in text for term in failure_terms):
            return "failure"
        if any(term in text for term in success_terms):
            return "success"
    return None


def _username(event: NetworkEvent) -> str | None:
    for key, value in _flatten_details(event.details):
        if key.endswith(("user", "username", "account")) and value:
            return str(value)[:120]
    return None


def _detail_text(event: NetworkEvent, name: str) -> str | None:
    value = event.details.get(name)
    return str(value) if value is not None and str(value) else None


def _credential_description(username: str | None, password: str | None) -> str:
    if username is not None and password is not None:
        return f'o usuário "{username}" e a senha "{password}"'
    if username is not None:
        return f'o usuário "{username}"'
    return f'a senha "{password}"'


def _occurred_before(left: NetworkEvent, right: NetworkEvent) -> bool:
    if left.occurred_at is None or right.occurred_at is None:
        return True
    return left.occurred_at <= right.occurred_at


def _dns_query(event: NetworkEvent) -> str | None:
    if event.application != "dns" and event.event_type != "dns":
        return None
    for key, value in _flatten_details(event.details):
        if key.endswith(("query", "rrname", "dns_query")) and value:
            return str(value).rstrip(".")
    return None


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
