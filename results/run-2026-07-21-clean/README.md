# run-2026-07-21 — análise LIMPA

Métricas com os períodos de incidente **cortados de todas as fases** (mesma base
temporal → igualdade de comparação). A pasta original com os dados em bruto
completos fica intacta em `../run-2026-07-21/`.

## Janelas excluídas (UTC), aplicadas às 3 fases
| Fase afetada | Início | Fim | Duração | Causa |
|---|---|---|---|---|
| Alpha | 04:02:23 | 04:07:55 | ~5,5 min | reboot do viper-gateway-a |
| Charlie | 15:03:13 | 15:57:25 | ~54 min | disco cheio no viper-gateway-c (broker EMQX em crash-loop) |
| Bravo | 16:36:36 | 18:48:46 | ~2h12 | disco cheio no viper-gateway-b (broker EMQX em crash-loop) |

União excluída ≈ 3h12 → janela válida analisada ≈ 20h48, idêntica para Alpha/Bravo/Charlie.

## Como reproduzir
```bash
cd Configurations/analysis
python3 extract_24h.py --start 2026-07-20T23:10:00Z --stop 2026-07-21T23:10:00Z \
  --exclude "2026-07-21T04:02:00/2026-07-21T04:08:30,2026-07-21T15:03:00/2026-07-21T15:58:00,2026-07-21T16:36:00/2026-07-21T18:49:30" \
  --out metrics
```

## Conteúdo
- `metrics/summary.csv` — estatísticas por fase/métrica (n, mean, median, p95, std, min, max)
- `metrics/raw/` — séries longas já filtradas (performance, handshake, environment, energy)
- `extract_clean_summary.txt` — tabela comparativa + deltas Alpha→Charlie→Bravo
