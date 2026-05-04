---
title: Windows AD Attack Playbook
hide:
  - toc
---

# Windows AD Attack Playbook
> This playbook is a work in progress based on my personal experience with HTB machines. I’m sharing it to document my learning journey and hopefully provide a helpful reference for others exploring Windows Active Directory.

> I am far from an expert and would love to hear your thoughts. If you notice a mistake, a more efficient way to chain attacks, or a new technique I missed, please open an issue or pull request. Your feedback and recommendations are greatly appreciated!

> This reference covering recon through domain dominance with explanations of **why** each technique works and **how** prerequisites chain into the next attack.

## How to use this playbook

This isn't a checklist; it's a chain. Every attack documents three things:

- :material-alert-circle:{ .twemoji } **What leads here** : the prerequisites that put you in position to use this technique.
- :material-information:{ .twemoji } **Why this works / how it chains** : the reasoning explaining *why* those prerequisites enable the attack.
- :material-arrow-right-bold-circle:{ .twemoji } **Leads to →** : what this attack sets up for the next step.

When you find yourself stuck, use the [Attack Decision Tree](reference/attack-decision-tree.md) to match your current position to the next viable move.

## Phases at a glance

<div class="grid cards" markdown>

-   :material-radar:{ .lg .middle } **[01–02 · Recon & Setup](01-reconnaissance-enumeration.md)**

    ---

    Map the attack surface. Configure Kerberos. Manage clock skew.

-   :material-key:{ .lg .middle } **[03–04 · Get Creds, then BloodHound](03-initial-access-no-creds.md)**

    ---

    ASREPRoast, spraying, NTLM relay → Kerberoast, ACL abuse, Shadow Credentials, RBCD.

-   :material-certificate:{ .lg .middle } **[05–06 · ADCS & gMSA](05-adcs-certificate-attacks-esc113.md)**

    ---

    The full ESC1–ESC13 family. gMSA password reading + key derivation.

-   :material-server-network:{ .lg .middle } **[07–10 · Service Abuse](07-jea-just-enough-administration-bypass.md)**

    ---

    JEA bypass, cross-forest, DLL hijack, fake WSUS : chained service-level escalation.

-   :material-arrow-right-bold:{ .lg .middle } **[11–14 · Lateral & Privesc](11-lateral-movement.md)**

    ---

    PtH/PtT/OPTH, MSSQL, Potatoes, DCSync, Golden/Silver tickets.

-   :material-database-lock:{ .lg .middle } **[15–18 · Enterprise Targets](15-laps-attacks.md)**

    ---

    LAPS, GPP, DSRM, SCCM. The places where credentials and admin paths hide.

-   :material-shield-link-variant:{ .lg .middle } **[19–23 · Trusts, Coercion, Relay](19-trust-attacks.md)**

    ---

    Forest trusts, PetitPotam, ntlmrelayx, WebDAV bypass.

-   :material-cloud-lock:{ .lg .middle } **[24–26 · Hybrid + OPSEC](24-azure-ad-hybrid-attacks.md)**

    ---

    Azure AD Connect, AMSI bypass, Snaffler.

</div>

## Reference

- :material-source-branch:{ .twemoji } [**Attack Decision Tree**](reference/attack-decision-tree.md) : find your current position, trace the chain.
- :material-tools:{ .twemoji } [**Quick Reference : Tools & Hash Modes**](reference/quick-reference-tools-hash-modes.md) : tool catalog + hashcat modes.
- :material-alert-decagram:{ .twemoji } [**Gotchas & Tips**](reference/gotchas-tips.md) : the hard-won lessons.

## Conventions

- `<IP>` and `<DC_IP>` mean substitute the actual IP.
- `domain.local` is the placeholder domain : replace with the engagement target.
- Every code block has a copy button (top right of the block).
- Search is ++slash++ or click the search bar.
- Press ++s++ to share/copy a link to the current page.

!!! danger "Authorized testing only"
    This material is for authorized penetration testing, red team engagements, and defensive research. Using these techniques against systems you don't have explicit permission to test is a crime in most jurisdictions.
