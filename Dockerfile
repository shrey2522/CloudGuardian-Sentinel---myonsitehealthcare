# CloudGuardian Sentinel - cloud-native container image
FROM python:3.12-slim

# terraform binary (remediation engine runs `terraform apply` in-container)
ARG TF_VERSION=1.9.8
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget unzip ca-certificates \
    && wget -q https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip \
    && unzip -o terraform_${TF_VERSION}_linux_amd64.zip -d /usr/local/bin \
    && rm terraform_${TF_VERSION}_linux_amd64.zip \
    && apt-get purge -y wget unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel/ ./sentinel/
COPY infra/ ./infra/

CMD ["python", "-m", "sentinel", "monitor"]
