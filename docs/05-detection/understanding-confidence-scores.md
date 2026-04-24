# Understanding Confidence Scores

Every event in trapnet's log that has a detected scanner type also has a `confidence` field. This document explains what confidence scores mean, why specific values were chosen for each scanner type, and how to interpret them when analyzing logs.

## What confidence represents

The confidence score is not a probability. It does not mean "there is an X% chance this is scanner Y." It is a relative ranking of how specific and reliable the evidence for each scanner type is. A score of 0.9 means the evidence is highly specific. A score of 0.5 means the evidence is plausible but not definitive.

The scale:

| Score | Meaning |
|-------|---------|
| 0.9   | Payload-specific signature, very unlikely to appear in other traffic |
| 0.85  | Strong behavioral signal that is nearly exclusive to this tool class |
| 0.8   | Well-known probe strings or strong multi-signal combination |
| 0.75  | Clear behavioral pattern with some ambiguity |
| 0.7   | Reasonable inference from limited evidence |
| 0.5   | Weak signal, plausible but not reliable |

## Assigned confidence values

```
METASPLOIT       0.9   - payload byte signatures specific to Metasploit modules
MASSCAN          0.85  - connection rate pattern almost exclusive to stateless scanners
NMAP             0.8   - known probe strings or systematic multi-port sweep
CREDENTIAL_STUFFER 0.75 - repeated auth attempts or common passwords
SHODAN           0.7   - crawler identifier or web-port banner grab behavior
GENERIC_SCANNER  0.5   - multi-port access with no stronger signal
```

## Why METASPLOIT gets 0.9

The EternalBlue SMB probe pattern and MS17-010 RDP probe pattern are specific byte sequences that Metasploit's modules construct. These sequences do not appear in legitimate traffic and are not reproduced by other widely-used scanners. When they appear, attribution to a Metasploit module is highly reliable. The score is not 1.0 because a sophisticated attacker could deliberately reproduce these bytes, and other tools built on Metasploit's libraries would produce the same signatures.

## Why GENERIC_SCANNER gets 0.5

Touching more than 3 unique ports from one IP in 60 seconds is the weakest signal. A monitoring system, a misconfigured client, or even a single developer running multiple tools could trigger this. The score of 0.5 indicates the inference is reasonable but should not be treated as high-confidence classification.

## How the detector picks the winner

When multiple scanner types have signals in the same event, the detector returns the highest-confidence match:

```python
best = max(candidates, key=lambda k: candidates[k][0])
```

This means a MASSCAN rate signal combined with an NMAP probe string produces a MASSCAN result (0.85 > 0.8). The NMAP signals are noted as indicators of a different scanner but the event is classified by the strongest evidence.

## Interpreting the indicators field

The `indicators` list explains why the classification was made. Examples:

```json
{
  "scanner_type": "NMAP",
  "confidence": 0.8,
  "indicators": [
    "Nmap probe string: b'GET / HTTP/1.0'",
    "9 unique ports hit in 60 seconds"
  ]
}
```

```json
{
  "scanner_type": "METASPLOIT",
  "confidence": 0.9,
  "indicators": [
    "EternalBlue SMB probe signature"
  ]
}
```

The indicators are what you would cite in a threat report. They describe the specific evidence, not just the conclusion.

## When scanner_type is null

Events with `scanner_type: null` and `confidence: 0.0` are connections that did not trigger any detection threshold. These are either:

- Legitimate misconfigured clients
- Very slow scans (below the rate thresholds)
- Single-port probes with no identifying payload
- Crawlers other than Shodan on non-web ports

Null detections are still valuable log entries. The raw payload and source IP may contain information useful for manual analysis.

## Further reading

- [How Nmap is detected](how-nmap-is-detected.md)
- [How Masscan is detected](how-masscan-is-detected.md)
- [How Metasploit is detected](how-metasploit-is-detected.md)
- [Detector explained](../03-code-walkthrough/detector-explained.md)
