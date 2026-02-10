# Honeypot Analysis

## Summary of Observed Attacks
During the testing phase, the honeypot captured two distinct types of interactions on port 22 (SSH).

Automated Protocol Identification (Handshake):

Source IP: 172.17.0.1

Client String: SSH-2.0-OpenSSH_for_Windows_9.5

Details: The client attempted a standard SSH key exchange negotiation. The honeypot successfully logged the exhaustive list of supported ciphers (AES-GCM, ChaCha20) and key types (ECDSA, Ed25519) before the connection terminated due to a protocol mismatch.

Manual Credential Injection:

Source IP: 172.17.0.1

Captured Input: password! / password...

Details: The honeypot successfully baited the user into providing plaintext strings by simulating an Access Denied response and a follow-up password prompt.
## Notable Patterns
Protocol Sensitivity: Real SSH clients (like OpenSSH for Windows) expect a sophisticated cryptographic handshake. Because the honeypot responds in plain text, real clients crash or disconnect quickly, which actually serves as a "dead man's switch" to prevent an attacker from gaining a real shell.

Information Leakage: The attacker's client string OpenSSH_for_Windows_9.5 identifies the host OS as Windows, giving the defender metadata about the environment the attack is coming from.

Plaintext Vulnerability: Using tools like netcat or telnet allows for the successful capture of strings that would otherwise be encrypted in a real SSH tunnel.
## Recommendations
Fail2Ban Integration: Automatically blacklist any IP that triggers a connection to the honeypot port, as there is no legitimate reason for a standard user to hit the decoy service.

Banner Customization: Change the banner to reflect an older, "vulnerable" version of OpenSSH (e.g., v7.2) to increase the likelihood of an attacker spending more time attempting known exploits, thus providing more logging data.

Alerting: Implement a webhook (e.g., Slack or Discord) to notify the security team in real-time when CAPTURED CREDENTIALS is triggered.