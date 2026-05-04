# Windows AD Attack Playbook

This playbook is a work in progress based on my personal experience with HTB machines. I’m sharing it to document my learning journey and hopefully provide a helpful reference for others exploring Windows Active Directory.

I am far from an expert and would love to hear your thoughts. If you notice a mistake, a more efficient way to chain attacks, or a new technique I missed, please open an issue or pull request. Your feedback and recommendations are greatly appreciated!

I make this as a reference playbook for Windows Active Directory (AD) techniques and reconnaissance used primarily for learning, red-team exercises, and defensive research.

It is covering recon → domain dominance, with explanations of **why** each technique works and **how** prerequisites chain into the next attack.

## Live site

https://sowatkheang.github.io/ad_attack_playbook/

## Local development

```bash
# Clone
git clone https://github.com/SowatKheang/ad_attack_playbook.git
cd ad_attack_playbook

# Install (Python 3.9+ recommended)
pip install -r requirements.txt

# Serve with live reload
mkdocs serve
# → open http://127.0.0.1:8000

# Build static site to ./site/
mkdocs build
```

## Purpose & scope
- Educational: explains concepts and common techniques for mapping and testing Windows AD in controlled environments.
- Reference: provides phase-based guidance and examples for lab practice and defensive learning.

## Ethics & legal
For authorized security testing, red team engagements, and defensive research only. Using these techniques against systems you don't have explicit permission to test is a crime in most jurisdictions.

### Community Support & Feedback

This project is a personal learning resource, and I know there is always more to learn. I’m very open to suggestions and would value your input to make this playbook more accurate and comprehensive.
How you can help:
- `Suggest Improvements`: Notice a typo or a clearer way to explain a concept?
- `Share Techniques`: Have a favorite tool or trick that isn't listed?
- `Report Errors`: If a command is outdated or a logic chain is flawed, please let me know.

If you have any suggestions or issues, feel free to open an [issue](https://github.com/SowatKheang/ad_attack_playbook/issues)

If you would like to contribute, feel free to create a [PR](https://github.com/SowatKheang/ad_attack_playbook/pulls)
