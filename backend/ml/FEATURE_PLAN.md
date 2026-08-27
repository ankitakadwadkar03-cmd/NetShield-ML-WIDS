# NetShield ML Feature Plan

## Goal

NetShield will use machine learning as the primary mechanism for
classifying WiFi traffic as normal or malicious.

Rule-based thresholds will not make the final attack decision.

Deterministic code may be used for packet parsing, feature extraction,
statistics, signal calculations, vendor lookup, and preprocessing.

## Initial Attack Classes

### Tier 1 - Direct Wireless Frame Behaviour
- Deauthentication
- Disassociation
- Reassociation

### Tier 2 - AP / Network Behaviour
- Rogue AP
- Evil Twin

### Tier 3 - Advanced Attacks
- KRACK
- Kr00k

Support for each attack will be finalized after inspecting AWID3
features and confirming that the required features can also be
extracted from live WiFi traffic.

## Existing Live Packet Fields

NetShield currently captures:

- Timestamp
- Packet Type
- Frame Type
- Source MAC
- Destination MAC
- BSSID
- Signal Strength

## Candidate Raw 802.11 Fields

The live packet extractor may later be extended to collect:

- Frame subtype
- Channel
- Frequency
- Sequence number
- Fragment number
- Retry flag
- Protected flag
- Duration
- Data rate
- EAPOL / WPA handshake information

## Candidate Window-Based ML Features

- total_packets
- packets_per_second
- beacon_count
- probe_request_count
- probe_response_count
- authentication_count
- deauth_count
- disassociation_count
- reassociation_count
- data_count
- control_count
- management_count
- unique_source_macs
- unique_destination_macs
- unique_bssids
- retry_count
- retry_ratio
- average_signal
- minimum_signal
- maximum_signal
- same_ssid_multiple_bssid_count
- security_change_count
- channel_change_count

## Important Constraint

The final training features must be features that can also be generated
by NetShield during live monitoring.

We will not blindly train using all AWID3 features.

Final feature set:

AWID3 available features
        INTERSECTION
NetShield live-extractable features
        =
ML training/inference features

## ML Pipeline

Live WiFi Traffic
        |
        v
Packet Parsing
        |
        v
Feature Extraction
        |
        v
Same Preprocessing Used During Training
        |
        v
ML Model
        |
        v
Normal / Attack
        |
        v
Attack Classification
        |
        v
Confidence + Incident Information
