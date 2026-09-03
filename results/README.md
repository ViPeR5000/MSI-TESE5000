# results/ — Evidências dos runs experimentais

Cada run de 24 h fica em `run-<YYYY-MM-DD>/`, recolhido por
`Configurations/analysis/collect_results.sh` **depois** do teste terminar.

## Estrutura de cada run

| Pasta | Conteúdo |
|---|---|
| `influx/` | Export do InfluxDB por fase e measurement (CSV), na janela do run: `telemetry_environment`, `telemetry_performance`, `telemetry_handshake`, `telemetry_relay`, `suricata_alerts`, `suricata_stats`, `energy` (só na Alpha, com tag `phase`) |
| `pcaps/` | Capturas full-take por VLAN do sensor SPAN (`alpha-vlan100`, `bravo-vlan20`, `charlie-vlan30`), rotação 500 MB |
| `suricata/` | `alerts.json` — eventos de alerta do `eve.json` do SPAN (`viper-suricata-a`) |
| `metrics/` | Saída do `extract_24h.py` — métricas crypto normalizadas (`crypto_cpu_us`, handshake) **e energia** (`power_w`, `energy_wh`) por fase |
| `status/` | `status_panel.html` + `validate_telemetry.txt` (snapshots no momento da recolha) |
| `loot/` | Artefactos exfiltrados pelo C2 por gateway (`vault`, `passwd`, `network_scan_*`, `file_list_*`, `sysinfo`, `process_list`, pcaps de bancada) — a evidência adversarial |
| `pics/` | Screenshots do run (injeção por fase, C2, mqtt overview) |
| `MANIFEST.txt` | Resumo do que foi recolhido |

`collect_results.sh` usa a janela UTC do run (override por env `START`/`STOP`); o
`extract_24h.py` interno corre na janela limpa de 24 h.

## Variante `-clean` (análise final)

`run-<dia>-clean/` contém só as **métricas com os incidentes cortados de todas as fases**
(igualdade de base temporal, ver `analysis/README.md` `--exclude`). A pasta original
`run-<dia>/` fica **sempre intacta** com o raw completo (gaps incluídos) para auditoria.


