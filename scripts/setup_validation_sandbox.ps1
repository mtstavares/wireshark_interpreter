$ErrorActionPreference = "Stop"

docker info | Out-Null
docker compose --profile build-only build validator-image

docker network inspect pcap-validation-egress *> $null
if ($LASTEXITCODE -ne 0) {
    docker network create --internal pcap-validation-egress | Out-Null
}

Write-Host "Validation sandbox image and internal network are ready."
