# ChaosDomainDumper

A Go tool to download, extract, and track updates of bug bounty domain lists from [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io/).

## How To Install
`go install github.com/m10x/ChaosDomainDumper@latest`

## 🔧 What It Does

- Fetches `index.json` from `https://chaos-data.projectdiscovery.io/`
- Organizes data by platform:
  - `Domains/` → full list of domains per program
  - `Updates/` → only newly added domains (on update)
- Detects updates based on the `last_updated` timestamp
- Stores the last run timestamp in `data/last_run.txt`
- Displays statistics for programs, domain files, and FQDN entries
