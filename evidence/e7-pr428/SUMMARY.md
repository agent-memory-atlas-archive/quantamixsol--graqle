# E7 (seed 20261020, 400 tasks) summary

Point estimate [CI low, CI high]; each cell is read from the JSON key shown in its header (`arms.<arm>.<metric>.{point,ci_low,ci_high}`) of that setting's `e7-report-run-63db454973b2.json`. `skipped` = the JSON holds `arms.<arm>.<metric>.skipped`.


## main (`main/e7-report-run-63db454973b2.json`)

| arm | `success_rate` | `safe_success_rate` | `mean_retries` | `mean_cost_usd` | `escalation_sla_adherence` | `explanation_faithfulness` | `escalations` | `loops_prevented` | `controller_failures` |
|---|---|---|---|---|---|---|---|---|---|
| `escalate` | 0.9575 [0.9450, 0.9700] | 0.9575 [0.9450, 0.9700] | 0.0000 [0.0000, 0.0000] | 5.0200 [5.0200, 5.0200] | 0.4975 [0.4450, 0.5500] | skipped | 400 | 0 | 0 |
| `graph_informed_replan` | 0.9975 [0.9950, 1.0000] | 0.9975 [0.9950, 1.0000] | 1.1550 [1.1400, 1.1700] | 0.7431 [0.7428, 0.7434] | 0.4643 [0.4286, 0.5000] | 0.8079 [0.8042, 0.8117] | 56 | 56 | 0 |
| `hold` | 0.0000 [0.0000, 0.0000] | 0.0000 [0.0000, 0.0000] | 0.0000 [0.0000, 0.0000] | 0.0200 [0.0200, 0.0200] | skipped | skipped | 0 | 0 | 0 |
| `prompt_retry` | 0.9575 [0.9500, 0.9650] | 0.9575 [0.9500, 0.9650] | 1.1025 [1.0850, 1.1200] | 4.4920 [4.4674, 4.5167] | 0.4691 [0.4633, 0.4749] | 0.1339 [0.1206, 0.1469] | 356 | 356 | 0 |

## sweepA (`sweepA/e7-report-run-63db454973b2.json`)

| arm | `success_rate` | `safe_success_rate` | `mean_retries` | `mean_cost_usd` | `escalation_sla_adherence` | `explanation_faithfulness` | `escalations` | `loops_prevented` | `controller_failures` |
|---|---|---|---|---|---|---|---|---|---|
| `escalate` | 0.9575 [0.9450, 0.9700] | 0.9575 [0.9450, 0.9700] | 0.0000 [0.0000, 0.0000] | 5.0200 [5.0200, 5.0200] | 0.4975 [0.4450, 0.5500] | skipped | 400 | 0 | 0 |
| `graph_informed_replan` | 0.9850 [0.9850, 0.9850] | 0.9850 [0.9850, 0.9850] | 1.2400 [1.2200, 1.2600] | 1.9698 [1.9194, 2.0202] | 0.5065 [0.4800, 0.5316] | 0.6000 [0.5829, 0.6176] | 154 | 154 | 0 |
| `hold` | 0.0000 [0.0000, 0.0000] | 0.0000 [0.0000, 0.0000] | 0.0000 [0.0000, 0.0000] | 0.0200 [0.0200, 0.0200] | skipped | skipped | 0 | 0 | 0 |
| `prompt_retry` | 0.9600 [0.9550, 0.9650] | 0.9600 [0.9550, 0.9650] | 1.1550 [1.1500, 1.1600] | 3.9931 [3.8682, 4.1180] | 0.4430 [0.4183, 0.4663] | 0.2226 [0.2043, 0.2409] | 316 | 316 | 0 |

## sweepB (`sweepB/e7-report-run-63db454973b2.json`)

| arm | `success_rate` | `safe_success_rate` | `mean_retries` | `mean_cost_usd` | `escalation_sla_adherence` | `explanation_faithfulness` | `escalations` | `loops_prevented` | `controller_failures` |
|---|---|---|---|---|---|---|---|---|---|
| `escalate` | 0.9575 [0.9450, 0.9700] | 0.9575 [0.9450, 0.9700] | 0.0000 [0.0000, 0.0000] | 5.0200 [5.0200, 5.0200] | 0.4975 [0.4450, 0.5500] | skipped | 400 | 0 | 0 |
| `graph_informed_replan` | 0.9975 [0.9950, 1.0000] | 0.9975 [0.9950, 1.0000] | 1.0850 [1.0800, 1.0900] | 0.3917 [0.3668, 0.4166] | 0.5357 [0.4667, 0.6154] | 0.8949 [0.8910, 0.8987] | 28 | 28 | 0 |
| `hold` | 0.0000 [0.0000, 0.0000] | 0.0000 [0.0000, 0.0000] | 0.0000 [0.0000, 0.0000] | 0.0200 [0.0200, 0.0200] | skipped | skipped | 0 | 0 | 0 |
| `prompt_retry` | 0.9575 [0.9500, 0.9650] | 0.9575 [0.9500, 0.9650] | 1.0375 [1.0350, 1.0400] | 4.7907 [4.7658, 4.8157] | 0.4684 [0.4660, 0.4709] | 0.0575 [0.0525, 0.0625] | 380 | 380 | 0 |
