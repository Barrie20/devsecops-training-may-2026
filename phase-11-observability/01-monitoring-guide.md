# Phase 11 — Observability & Monitoring

---

## The Three Pillars of Observability

```
METRICS              LOGS                 TRACES
(What happened?)     (Why it happened?)   (Where it happened?)

Prometheus           ELK Stack            Jaeger
Grafana              CloudWatch Logs      AWS X-Ray
CloudWatch           Fluentd/Fluent Bit   OpenTelemetry
Datadog              Loki                 Zipkin
```

**Security Observability = Seeing attacks in real-time**

---

## Prometheus — Metrics Collection

Prometheus scrapes metrics from your applications and infrastructure.

### Key Concepts:
- **Metric types:** Counter, Gauge, Histogram, Summary
- **Scraping:** Prometheus pulls metrics from endpoints every 15-30s
- **PromQL:** Query language for metrics
- **Alerting:** Rules that fire when thresholds are breached

### Security Metrics to Monitor:

```yaml
# prometheus/alerts/security-alerts.yml
groups:
  - name: security-alerts
    rules:
      # Alert: Too many 401/403 responses (brute force?)
      - alert: HighAuthFailureRate
        expr: |
          sum(rate(http_requests_total{status=~"401|403"}[5m])) 
          / sum(rate(http_requests_total[5m])) > 0.1
        for: 5m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "High authentication failure rate ({{ $value | humanizePercentage }})"
          description: "More than 10% of requests are failing auth. Possible brute force attack."

      # Alert: Unusual outbound traffic (data exfiltration?)
      - alert: UnusualEgressTraffic
        expr: |
          sum(rate(container_network_transmit_bytes_total[5m])) by (pod) 
          > 10485760
        for: 10m
        labels:
          severity: high
        annotations:
          summary: "Pod {{ $labels.pod }} sending >10MB/s outbound"

      # Alert: Container running as root
      - alert: ContainerRunningAsRoot
        expr: |
          container_processes{user="root"} > 0
        labels:
          severity: medium
        annotations:
          summary: "Container {{ $labels.container }} running as root"

      # Alert: Pod restarting frequently (crash loop = possible attack)
      - alert: PodCrashLooping
        expr: |
          rate(kube_pod_container_status_restarts_total[15m]) > 0.1
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "Pod {{ $labels.pod }} is crash-looping"

      # Alert: Disk filling up (ransomware? log bomb?)
      - alert: DiskSpaceCritical
        expr: |
          (node_filesystem_avail_bytes / node_filesystem_size_bytes) < 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Disk space below 10% on {{ $labels.instance }}"
```

### PromQL Examples for Security:

```promql
# Failed login rate over time
rate(login_attempts_total{status="failed"}[5m])

# Top 5 IPs by failed requests
topk(5, sum by (source_ip) (rate(http_requests_total{status="401"}[1h])))

# Unusual CPU spike (crypto mining?)
avg(rate(container_cpu_usage_seconds_total[5m])) by (pod) > 0.8

# Network connections per pod (lateral movement?)
sum by (pod) (container_network_receive_bytes_total)
```

---

## Grafana — Visualization & Dashboards

### Security Dashboard Panels:

```json
{
  "dashboard": {
    "title": "Security Operations Dashboard",
    "panels": [
      {
        "title": "Failed Authentication Rate",
        "type": "timeseries",
        "targets": [{
          "expr": "sum(rate(http_requests_total{status='401'}[5m]))"
        }]
      },
      {
        "title": "Active Security Alerts",
        "type": "stat",
        "targets": [{
          "expr": "count(ALERTS{alertstate='firing', severity='critical'})"
        }]
      },
      {
        "title": "Top Attacking IPs",
        "type": "table",
        "targets": [{
          "expr": "topk(10, sum by (source_ip) (increase(blocked_requests_total[1h])))"
        }]
      },
      {
        "title": "Container Vulnerabilities",
        "type": "gauge",
        "targets": [{
          "expr": "sum(trivy_vulnerability_count{severity='critical'})"
        }]
      }
    ]
  }
}
```

---

## ELK Stack — Centralized Logging

ELK = Elasticsearch + Logstash + Kibana

```
Applications → Filebeat/Fluent Bit → Logstash → Elasticsearch → Kibana
                (collect)            (process)    (store/index)   (visualize)
```

### Security Log Queries (Kibana/KQL):

```
# Find failed SSH logins
message: "Failed password" AND source: "/var/log/auth.log"

# Find privilege escalation
message: "sudo" AND message: "COMMAND" AND NOT user: "deploy"

# Find unusual API access patterns
status_code: 403 AND NOT source_ip: "10.0.0.0/8"

# Find potential SQL injection attempts
request_uri: *"SELECT"* OR request_uri: *"UNION"* OR request_uri: *"DROP"*

# Find data exfiltration (large responses)
response_bytes: > 10000000 AND NOT endpoint: "/api/export"
```

### Fluent Bit Configuration (Lightweight Log Collector):

```ini
# fluent-bit.conf
[SERVICE]
    Flush        5
    Log_Level    info

[INPUT]
    Name         tail
    Path         /var/log/containers/*.log
    Parser       docker
    Tag          kube.*
    Refresh_Interval 5

[FILTER]
    Name         kubernetes
    Match        kube.*
    Merge_Log    On

# Security: Redact sensitive data before shipping
[FILTER]
    Name         modify
    Match        *
    Condition    Key_Value_Matches message password=.*
    Set          message [REDACTED - contained password]

[OUTPUT]
    Name         es
    Match        *
    Host         elasticsearch.monitoring.svc
    Port         9200
    Index        security-logs
    TLS          On
    TLS.Verify   On
```

---

## CloudWatch — AWS Native Monitoring

### Security-Focused CloudWatch Setup:

```bash
# Create metric filter for failed console logins
aws logs put-metric-filter \
    --log-group-name CloudTrail/logs \
    --filter-name ConsoleLoginFailures \
    --filter-pattern '{ ($.eventName = "ConsoleLogin") && ($.errorMessage = "Failed authentication") }' \
    --metric-transformations \
        metricName=ConsoleLoginFailures,metricNamespace=SecurityMetrics,metricValue=1

# Create alarm
aws cloudwatch put-metric-alarm \
    --alarm-name "ConsoleLoginFailures" \
    --metric-name ConsoleLoginFailures \
    --namespace SecurityMetrics \
    --statistic Sum \
    --period 300 \
    --threshold 3 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 1 \
    --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:security-alerts

# CloudWatch Logs Insights queries
# Find root account usage
fields @timestamp, userIdentity.type, sourceIPAddress, eventName
| filter userIdentity.type = "Root"
| sort @timestamp desc

# Find security group changes
fields @timestamp, userIdentity.userName, requestParameters.groupId
| filter eventName in ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"]
| sort @timestamp desc

# Find IAM policy changes
fields @timestamp, userIdentity.userName, eventName, requestParameters
| filter eventSource = "iam.amazonaws.com"
| filter eventName like /Put|Create|Attach|Delete/
| sort @timestamp desc
```

---

## Incident Detection Patterns

### Pattern 1: Brute Force Detection
```
Signal: >10 failed logins from same IP in 5 minutes
Action: Block IP at WAF, alert security team
Tool: Prometheus alert + WAF automation
```

### Pattern 2: Data Exfiltration
```
Signal: Unusual outbound data volume from a service
Action: Isolate service, capture network traffic
Tool: VPC Flow Logs + CloudWatch alarm
```

### Pattern 3: Privilege Escalation
```
Signal: User assumes role they've never used before
Action: Alert, review CloudTrail, potentially revoke
Tool: GuardDuty + CloudWatch Events
```

### Pattern 4: Lateral Movement
```
Signal: Service accessing resources outside its normal pattern
Action: Network isolation, investigate compromised credentials
Tool: VPC Flow Logs + Network Policy alerts
```

---

## Memory Technique: "SEE ALERT ACT"

Observability workflow:
- **SEE** — Collect metrics, logs, traces (Prometheus, ELK, Jaeger)
- **ALERT** — Define thresholds and anomalies (Alertmanager, PagerDuty)
- **ACT** — Automated response + human investigation (runbooks, SOAR)

---

## Common Mistakes

1. **Alert fatigue** — Too many alerts = all get ignored. Tune thresholds.
2. **No log retention policy** — Logs fill disk, or you can't investigate old incidents
3. **Monitoring only availability** — Must also monitor security signals
4. **No correlation** — Individual signals are weak; correlated signals are strong
5. **Logs without context** — Include request ID, user, IP in every log line
6. **No dashboards** — If nobody looks at it, it doesn't exist

---

## Interview Insight

**Q: "How would you design a monitoring system to detect security incidents?"**

"I'd build a layered detection system:

**Layer 1 — Collection:**
- Metrics: Prometheus (infrastructure + application)
- Logs: Fluent Bit → Elasticsearch (centralized, searchable)
- Traces: OpenTelemetry → Jaeger (request flow visibility)
- Cloud: CloudTrail + VPC Flow Logs + GuardDuty

**Layer 2 — Detection:**
- Threshold alerts (known bad: >10 failed logins)
- Anomaly detection (unknown bad: unusual traffic patterns)
- Correlation rules (combine weak signals into strong indicators)
- Threat intelligence feeds (known malicious IPs/domains)

**Layer 3 — Response:**
- Automated: Block IP at WAF, isolate pod, revoke credentials
- Semi-automated: Create ticket, page on-call, gather context
- Manual: Incident commander, forensics, communication

**Key metrics I'd track:**
- MTTD (Mean Time to Detect) — target: <5 minutes
- MTTR (Mean Time to Respond) — target: <30 minutes
- False positive rate — target: <10%
- Coverage — % of services with security monitoring"
