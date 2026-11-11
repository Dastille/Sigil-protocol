# Real-data (Instagram Sigil sample) per-point results

Run 2026-11-11 02:01–02:16 ET on Parrot (nice 19, 12 threads, 930 s). See RATCHET-REPAIR.md §4b.

**Reflection 12-of-16 (as stored) — B4K 6.25%** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 36/54 | 67% | 0 | 0 | 14 | 5271.1 | 20073 |
| a' harness model of today | 35/54 | 65% | 0 | 0 | 0 | 891.4 | 8582 |
| b hard marks 4096/crc32 | 52/54 | 96% | 0 | 0 | 0 | 63.3 | 1043 |
| b hard marks 64/crc32 | 52/54 | 96% | 0 | 0 | 0 | 69.1 | 1046 |
| c hint marks 64/crc32 | 35/54 | 65% | 0 | 17 | 0 | 842.0 | 12144 |
| d ratchet 64/crc32 +2bit | 52/54 | 96% | 0 | 2 | 0 | 76.8 | 1189 |
| d ratchet 512/crc32 +2bit | 52/54 | 96% | 0 | 2 | 0 | 70.3 | 1023 |
| d chain-hybrid 64/crc32 +2bit | 52/54 | 96% | 0 | 2 | 0 | 84.6 | 1056 |
| d chain-pure 64/crc32 +2bit | 52/54 | 96% | 0 | 1 | 1 | 350.7 | 9191 |

**Reflection 12-of-16 (as stored) — L4+BER 1.9e-6** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 12/54 | 22% | 0 | 0 | 14 | 5356.4 | 20060 |
| a' harness model of today | 12/54 | 22% | 0 | 42 | 0 | 30.2 | 302 |
| b hard marks 4096/crc32 | 12/54 | 22% | 0 | 0 | 0 | 0.4 | 4 |
| b hard marks 64/crc32 | 12/54 | 22% | 0 | 0 | 0 | 0.5 | 4 |
| c hint marks 64/crc32 | 12/54 | 22% | 0 | 42 | 0 | 36.2 | 370 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 101.7 | 987 |
| d ratchet 512/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 94.8 | 1008 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 94.8 | 1081 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 93.8 | 1023 |

**Reflection 12-of-16 (as stored) — S512 2.00%** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 40/54 | 74% | 0 | 0 | 12 | 4520.6 | 20040 |
| a' harness model of today | 40/54 | 74% | 0 | 0 | 0 | 445.6 | 4454 |
| b hard marks 4096/crc32 | 32/54 | 59% | 0 | 0 | 0 | 3.9 | 22 |
| b hard marks 64/crc32 | 54/54 | 100% | 0 | 0 | 0 | 92.1 | 994 |
| c hint marks 64/crc32 | 42/54 | 78% | 0 | 12 | 0 | 463.6 | 5153 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 98.5 | 1086 |
| d ratchet 512/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 85.5 | 1028 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 91.6 | 1021 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 92.9 | 1084 |

**Reflection 12-of-16 (as stored) — L4+BER 1.5e-5** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 8/54 | 15% | 0 | 0 | 14 | 5734.0 | 20055 |
| a' harness model of today | 8/54 | 15% | 0 | 46 | 0 | 28.0 | 274 |
| b hard marks 4096/crc32 | 8/54 | 15% | 0 | 0 | 0 | 0.2 | 3 |
| b hard marks 64/crc32 | 8/54 | 15% | 0 | 0 | 0 | 0.2 | 2 |
| c hint marks 64/crc32 | 8/54 | 15% | 0 | 46 | 0 | 33.2 | 346 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 104.2 | 1051 |
| d ratchet 512/crc32 +2bit | 50/54 | 93% | 0 | 4 | 0 | 71.8 | 722 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 103.9 | 1074 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 105.0 | 1123 |

**Reflection 12-of-16 (as stored) — L4+BER 1.2e-4** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 3/54 | 6% | 0 | 0 | 14 | 5873.7 | 20066 |
| a' harness model of today | 3/54 | 6% | 0 | 51 | 0 | 29.6 | 291 |
| b hard marks 4096/crc32 | 3/54 | 6% | 0 | 0 | 0 | 0.2 | 4 |
| b hard marks 64/crc32 | 3/54 | 6% | 0 | 0 | 0 | 0.3 | 4 |
| c hint marks 64/crc32 | 3/54 | 6% | 0 | 51 | 0 | 35.8 | 352 |
| d ratchet 64/crc32 +2bit | 37/54 | 69% | 0 | 17 | 0 | 60.3 | 534 |
| d ratchet 512/crc32 +2bit | 13/54 | 24% | 0 | 41 | 0 | 148.2 | 1478 |
| d chain-hybrid 64/crc32 +2bit | 37/54 | 69% | 0 | 17 | 0 | 57.6 | 542 |
| d chain-pure 64/crc32 +2bit | 37/54 | 69% | 0 | 17 | 0 | 53.1 | 499 |

**Reflection 12-of-16 (as stored) — BER 6.1e-5** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 52/54 | 96% | 0 | 0 | 2 | 870.3 | 20044 |
| a' harness model of today | 52/54 | 96% | 0 | 0 | 0 | 92.0 | 1103 |
| b hard marks 4096/crc32 | 12/54 | 22% | 0 | 0 | 0 | 0.5 | 11 |
| b hard marks 64/crc32 | 46/54 | 85% | 0 | 0 | 0 | 32.4 | 448 |
| c hint marks 64/crc32 | 54/54 | 100% | 0 | 0 | 0 | 121.2 | 1241 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 107.9 | 1195 |
| d ratchet 512/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 120.4 | 1310 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 108.7 | 1185 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 104.6 | 1040 |

**Reflection 12-of-16 (as stored) — S512 6.25%** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 13/54 | 24% | 0 | 0 | 14 | 5710.0 | 20056 |
| a' harness model of today | 13/54 | 24% | 0 | 0 | 0 | 942.8 | 8112 |
| b hard marks 4096/crc32 | 12/54 | 22% | 0 | 0 | 0 | 0.2 | 3 |
| b hard marks 64/crc32 | 38/54 | 70% | 0 | 0 | 0 | 10.7 | 156 |
| c hint marks 64/crc32 | 21/54 | 39% | 0 | 17 | 0 | 289.2 | 4386 |
| d ratchet 64/crc32 +2bit | 38/54 | 70% | 0 | 16 | 0 | 43.9 | 431 |
| d ratchet 512/crc32 +2bit | 38/54 | 70% | 0 | 16 | 0 | 38.4 | 385 |
| d chain-hybrid 64/crc32 +2bit | 38/54 | 70% | 0 | 16 | 0 | 51.6 | 481 |
| d chain-pure 64/crc32 +2bit | 38/54 | 70% | 0 | 12 | 4 | 909.8 | 8294 |

**Reflection 12-of-16 (as stored) — BER 2.4e-4** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 42/54 | 78% | 0 | 0 | 10 | 3855.5 | 20049 |
| a' harness model of today | 42/54 | 78% | 0 | 0 | 0 | 83.0 | 833 |
| b hard marks 4096/crc32 | 8/54 | 15% | 0 | 0 | 0 | 0.3 | 5 |
| b hard marks 64/crc32 | 12/54 | 22% | 0 | 0 | 0 | 0.5 | 5 |
| c hint marks 64/crc32 | 46/54 | 85% | 0 | 0 | 0 | 68.7 | 768 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 125.7 | 1474 |
| d ratchet 512/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 273.5 | 3375 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 111.1 | 1434 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 108.2 | 1473 |

**Reflection 12-of-16 (as stored) — BER 9.8e-4** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 16/54 | 30% | 0 | 0 | 14 | 5865.1 | 20048 |
| a' harness model of today | 16/54 | 30% | 0 | 0 | 0 | 203.7 | 2208 |
| b hard marks 4096/crc32 | 1/54 | 2% | 0 | 0 | 0 | 0.4 | 7 |
| b hard marks 64/crc32 | 1/54 | 2% | 0 | 0 | 0 | 0.3 | 7 |
| c hint marks 64/crc32 | 16/54 | 30% | 0 | 0 | 0 | 4.9 | 21 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 349.0 | 3931 |
| d ratchet 512/crc32 +2bit | 45/54 | 83% | 0 | 9 | 0 | 334.7 | 3027 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 317.0 | 3377 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 284.8 | 2513 |

**Reflection 12-of-16 (as stored) — L2+BER 9.8e-4** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 0/54 | 0% | 0 | 0 | 14 | 5785.6 | 20070 |
| a' harness model of today | 3/54 | 6% | 0 | 0 | 0 | 149.4 | 1449 |
| b hard marks 4096/crc32 | 0/54 | 0% | 0 | 0 | 0 | 0.1 | 2 |
| b hard marks 64/crc32 | 0/54 | 0% | 0 | 0 | 0 | 0.1 | 1 |
| c hint marks 64/crc32 | 3/54 | 6% | 0 | 0 | 0 | 0.3 | 2 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 321.6 | 3186 |
| d ratchet 512/crc32 +2bit | 12/54 | 22% | 0 | 38 | 4 | 1130.1 | 10953 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 287.1 | 3325 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 268.7 | 2844 |

**Reflection 12-of-16 (as stored) — L4+BER 1.5e-5+rot** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 10/54 | 19% | 0 | 0 | 14 | 5733.8 | 20055 |
| a' harness model of today | 10/54 | 19% | 0 | 44 | 0 | 31.0 | 303 |
| b hard marks 4096/crc32 | 10/54 | 19% | 0 | 2 | 0 | 0.5 | 8 |
| b hard marks 64/crc32 | 10/54 | 19% | 0 | 1 | 0 | 0.4 | 5 |
| c hint marks 64/crc32 | 10/54 | 19% | 0 | 44 | 0 | 37.7 | 349 |
| d ratchet 64/crc32 +2bit | 19/54 | 35% | 0 | 35 | 0 | 41.1 | 390 |
| d ratchet 512/crc32 +2bit | 29/54 | 54% | 0 | 25 | 0 | 49.3 | 485 |
| d chain-hybrid 64/crc32 +2bit | 16/54 | 30% | 0 | 38 | 0 | 43.7 | 469 |
| d chain-pure 64/crc32 +2bit | 15/54 | 28% | 0 | 39 | 0 | 40.3 | 414 |

**Seal 8-of-16 (same payloads re-sealed) — BER 6.1e-5** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 54/54 | 100% | 0 | 0 | 0 | 185.8 | 1591 |
| a' harness model of today | 54/54 | 100% | 0 | 0 | 0 | 125.8 | 1418 |
| b hard marks 4096/crc32 | 12/54 | 22% | 0 | 0 | 0 | 0.2 | 4 |
| b hard marks 64/crc32 | 54/54 | 100% | 0 | 0 | 0 | 120.9 | 1385 |
| c hint marks 64/crc32 | 54/54 | 100% | 0 | 0 | 0 | 132.7 | 1532 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 112.3 | 1299 |
| d ratchet 512/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 103.0 | 1240 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 116.5 | 1367 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 114.6 | 1354 |

**Reflection 12-of-16 (as stored) — BER 1.9e-3** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 7/54 | 13% | 0 | 0 | 14 | 5913.3 | 20049 |
| a' harness model of today | 7/54 | 13% | 0 | 0 | 0 | 365.1 | 4036 |
| b hard marks 4096/crc32 | 0/54 | 0% | 0 | 0 | 0 | 0.2 | 2 |
| b hard marks 64/crc32 | 0/54 | 0% | 0 | 0 | 0 | 0.1 | 3 |
| c hint marks 64/crc32 | 7/54 | 13% | 0 | 0 | 0 | 1.3 | 6 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 651.6 | 6532 |
| d ratchet 512/crc32 +2bit | 28/54 | 52% | 0 | 22 | 4 | 513.0 | 4679 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 619.3 | 5656 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 594.1 | 5294 |

**Seal 8-of-16 (same payloads re-sealed) — S512 6.25%** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 40/53 | 75% | 0 | 0 | 11 | 4353.0 | 20073 |
| a' harness model of today | 40/53 | 75% | 0 | 0 | 0 | 1268.5 | 13527 |
| b hard marks 4096/crc32 | 27/53 | 51% | 0 | 0 | 0 | 3.4 | 25 |
| b hard marks 64/crc32 | 53/53 | 100% | 0 | 0 | 0 | 100.8 | 864 |
| c hint marks 64/crc32 | 53/53 | 100% | 0 | 0 | 0 | 1212.5 | 11843 |
| d ratchet 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 102.8 | 1029 |
| d ratchet 512/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 91.4 | 782 |
| d chain-hybrid 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 107.5 | 993 |
| d chain-pure 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 114.1 | 1335 |

**Reflection 12-of-16 (as stored) — BER 3.9e-3** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 2/54 | 4% | 0 | 0 | 14 | 5857.2 | 20041 |
| a' harness model of today | 2/54 | 4% | 0 | 0 | 0 | 576.8 | 7061 |
| b hard marks 4096/crc32 | 0/54 | 0% | 0 | 0 | 0 | 0.3 | 8 |
| b hard marks 64/crc32 | 0/54 | 0% | 0 | 0 | 0 | 0.2 | 6 |
| c hint marks 64/crc32 | 2/54 | 4% | 0 | 0 | 0 | 0.6 | 8 |
| d ratchet 64/crc32 +2bit | 27/54 | 50% | 0 | 23 | 4 | 830.8 | 7123 |
| d ratchet 512/crc32 +2bit | 11/54 | 20% | 0 | 38 | 5 | 988.5 | 5676 |
| d chain-hybrid 64/crc32 +2bit | 27/54 | 50% | 0 | 23 | 4 | 835.2 | 5309 |
| d chain-pure 64/crc32 +2bit | 27/54 | 50% | 0 | 23 | 4 | 1049.8 | 8033 |

**Seal 8-of-16 (same payloads re-sealed) — BER 9.8e-4** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 50/54 | 93% | 0 | 0 | 4 | 1641.6 | 20066 |
| a' harness model of today | 50/54 | 93% | 0 | 0 | 0 | 281.6 | 2335 |
| b hard marks 4096/crc32 | 1/54 | 2% | 0 | 0 | 0 | 0.4 | 9 |
| b hard marks 64/crc32 | 8/54 | 15% | 0 | 0 | 0 | 0.4 | 9 |
| c hint marks 64/crc32 | 50/54 | 93% | 0 | 0 | 0 | 216.8 | 2691 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 182.5 | 2142 |
| d ratchet 512/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 427.2 | 4104 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 182.3 | 2075 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 178.5 | 2039 |

**Seal 8-of-16 (same payloads re-sealed) — S512 12.50%** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 14/53 | 26% | 0 | 0 | 14 | 6568.2 | 20064 |
| a' harness model of today | 14/53 | 26% | 0 | 0 | 0 | 1712.8 | 14387 |
| b hard marks 4096/crc32 | 12/53 | 23% | 0 | 0 | 0 | 0.2 | 2 |
| b hard marks 64/crc32 | 52/53 | 98% | 0 | 0 | 0 | 92.6 | 944 |
| c hint marks 64/crc32 | 52/53 | 98% | 0 | 0 | 0 | 1568.7 | 14078 |
| d ratchet 64/crc32 +2bit | 52/53 | 98% | 0 | 1 | 0 | 98.7 | 810 |
| d ratchet 512/crc32 +2bit | 52/53 | 98% | 0 | 1 | 0 | 91.4 | 749 |
| d chain-hybrid 64/crc32 +2bit | 52/53 | 98% | 0 | 1 | 0 | 105.7 | 1011 |
| d chain-pure 64/crc32 +2bit | 52/53 | 98% | 0 | 0 | 1 | 308.0 | 10762 |

**Seal 8-of-16 (same payloads re-sealed) — BER 1.9e-3** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 42/54 | 78% | 0 | 0 | 11 | 4161.5 | 20060 |
| a' harness model of today | 42/54 | 78% | 0 | 0 | 0 | 509.9 | 5290 |
| b hard marks 4096/crc32 | 1/54 | 2% | 0 | 0 | 0 | 0.2 | 2 |
| b hard marks 64/crc32 | 1/54 | 2% | 0 | 0 | 0 | 0.1 | 2 |
| c hint marks 64/crc32 | 42/54 | 78% | 0 | 0 | 0 | 128.2 | 1299 |
| d ratchet 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 655.2 | 7596 |
| d ratchet 512/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 665.6 | 7605 |
| d chain-hybrid 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 611.1 | 6868 |
| d chain-pure 64/crc32 +2bit | 54/54 | 100% | 0 | 0 | 0 | 554.6 | 4758 |

**Seal 8-of-16 (same payloads re-sealed) — BER 3.9e-3** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 20/54 | 37% | 0 | 0 | 14 | 6290.5 | 20105 |
| a' harness model of today | 20/54 | 37% | 0 | 0 | 0 | 743.9 | 6265 |
| b hard marks 4096/crc32 | 0/54 | 0% | 0 | 0 | 0 | 0.4 | 11 |
| b hard marks 64/crc32 | 0/54 | 0% | 0 | 0 | 0 | 0.3 | 11 |
| c hint marks 64/crc32 | 20/54 | 37% | 0 | 0 | 0 | 34.8 | 201 |
| d ratchet 64/crc32 +2bit | 50/54 | 93% | 0 | 0 | 4 | 752.4 | 5150 |
| d ratchet 512/crc32 +2bit | 46/54 | 85% | 0 | 4 | 4 | 727.6 | 7679 |
| d chain-hybrid 64/crc32 +2bit | 50/54 | 93% | 0 | 0 | 4 | 775.6 | 6555 |
| d chain-pure 64/crc32 +2bit | 50/54 | 93% | 0 | 0 | 4 | 755.8 | 6539 |

**Seal 8-of-16 (same payloads re-sealed) — B4K 12.50%** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 35/53 | 66% | 0 | 0 | 14 | 5481.1 | 20064 |
| a' harness model of today | 35/53 | 66% | 0 | 0 | 0 | 1765.5 | 17645 |
| b hard marks 4096/crc32 | 53/53 | 100% | 0 | 0 | 0 | 106.3 | 1120 |
| b hard marks 64/crc32 | 53/53 | 100% | 0 | 0 | 0 | 114.7 | 1106 |
| c hint marks 64/crc32 | 53/53 | 100% | 0 | 0 | 0 | 1701.2 | 17333 |
| d ratchet 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 114.1 | 1084 |
| d ratchet 512/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 101.9 | 981 |
| d chain-hybrid 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 107.7 | 1080 |
| d chain-pure 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 108.0 | 1005 |

**Reflection 12-of-16 (as stored) — BER 1.9e-3+rot** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 10/54 | 19% | 0 | 0 | 14 | 5794.6 | 20050 |
| a' harness model of today | 10/54 | 19% | 0 | 0 | 0 | 346.3 | 3121 |
| b hard marks 4096/crc32 | 10/54 | 19% | 0 | 0 | 0 | 198.8 | 3026 |
| b hard marks 64/crc32 | 10/54 | 19% | 0 | 0 | 0 | 243.5 | 4112 |
| c hint marks 64/crc32 | 10/54 | 19% | 0 | 0 | 0 | 240.1 | 3982 |
| d ratchet 64/crc32 +2bit | 10/54 | 19% | 0 | 8 | 0 | 503.0 | 5519 |
| d ratchet 512/crc32 +2bit | 10/54 | 19% | 0 | 10 | 0 | 602.8 | 8751 |
| d chain-hybrid 64/crc32 +2bit | 10/54 | 19% | 0 | 7 | 0 | 500.1 | 7670 |
| d chain-pure 64/crc32 +2bit | 10/54 | 19% | 0 | 7 | 0 | 499.0 | 8692 |

**Seal 8-of-16 (same payloads re-sealed) — L8+BER 1.2e-4** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 1/53 | 2% | 0 | 0 | 14 | 6551.7 | 20108 |
| a' harness model of today | 1/53 | 2% | 0 | 52 | 0 | 52.6 | 482 |
| b hard marks 4096/crc32 | 1/53 | 2% | 0 | 0 | 0 | 0.2 | 2 |
| b hard marks 64/crc32 | 1/53 | 2% | 0 | 0 | 0 | 0.1 | 1 |
| c hint marks 64/crc32 | 1/53 | 2% | 0 | 52 | 0 | 51.3 | 530 |
| d ratchet 64/crc32 +2bit | 38/53 | 72% | 0 | 15 | 0 | 72.9 | 712 |
| d ratchet 512/crc32 +2bit | 13/53 | 25% | 0 | 40 | 0 | 150.3 | 1549 |
| d chain-hybrid 64/crc32 +2bit | 38/53 | 72% | 0 | 15 | 0 | 69.8 | 725 |
| d chain-pure 64/crc32 +2bit | 38/53 | 72% | 0 | 15 | 0 | 65.5 | 635 |

**Seal 8-of-16 (same payloads re-sealed) — BER 5.9e-3** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 9/54 | 17% | 0 | 0 | 14 | 6406.7 | 20075 |
| a' harness model of today | 9/54 | 17% | 0 | 0 | 0 | 1090.8 | 11899 |
| b hard marks 4096/crc32 | 0/54 | 0% | 0 | 0 | 0 | 0.2 | 4 |
| b hard marks 64/crc32 | 0/54 | 0% | 0 | 0 | 0 | 0.2 | 4 |
| c hint marks 64/crc32 | 9/54 | 17% | 0 | 0 | 0 | 5.5 | 37 |
| d ratchet 64/crc32 +2bit | 48/54 | 89% | 0 | 2 | 4 | 842.7 | 6780 |
| d ratchet 512/crc32 +2bit | 23/54 | 43% | 0 | 27 | 4 | 859.4 | 5309 |
| d chain-hybrid 64/crc32 +2bit | 48/54 | 89% | 0 | 2 | 4 | 772.9 | 5149 |
| d chain-pure 64/crc32 +2bit | 48/54 | 89% | 0 | 2 | 4 | 856.3 | 6512 |

**Seal 8-of-16 (same payloads re-sealed) — L8+BER 1.5e-5** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 8/53 | 15% | 0 | 0 | 14 | 6562.8 | 20065 |
| a' harness model of today | 8/53 | 15% | 0 | 45 | 0 | 48.2 | 470 |
| b hard marks 4096/crc32 | 8/53 | 15% | 0 | 0 | 0 | 0.2 | 1 |
| b hard marks 64/crc32 | 8/53 | 15% | 0 | 0 | 0 | 0.2 | 2 |
| c hint marks 64/crc32 | 8/53 | 15% | 0 | 45 | 0 | 51.9 | 531 |
| d ratchet 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 113.7 | 892 |
| d ratchet 512/crc32 +2bit | 48/53 | 91% | 0 | 5 | 0 | 95.7 | 917 |
| d chain-hybrid 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 112.4 | 842 |
| d chain-pure 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 112.3 | 861 |

**Seal 8-of-16 (same payloads re-sealed) — L8+BER 1.9e-6** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 12/53 | 23% | 0 | 0 | 14 | 5943.0 | 20063 |
| a' harness model of today | 12/53 | 23% | 0 | 41 | 0 | 44.7 | 490 |
| b hard marks 4096/crc32 | 12/53 | 23% | 0 | 0 | 0 | 0.4 | 5 |
| b hard marks 64/crc32 | 12/53 | 23% | 0 | 0 | 0 | 0.6 | 6 |
| c hint marks 64/crc32 | 12/53 | 23% | 0 | 41 | 0 | 49.6 | 557 |
| d ratchet 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 117.4 | 1267 |
| d ratchet 512/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 111.0 | 1196 |
| d chain-hybrid 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 114.9 | 1128 |
| d chain-pure 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 116.3 | 1212 |

**Seal 8-of-16 (same payloads re-sealed) — L8+BER 1.5e-5+rot** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 11/53 | 21% | 0 | 0 | 14 | 6517.5 | 20064 |
| a' harness model of today | 11/53 | 21% | 0 | 42 | 0 | 44.6 | 454 |
| b hard marks 4096/crc32 | 11/53 | 21% | 0 | 2 | 0 | 0.6 | 13 |
| b hard marks 64/crc32 | 11/53 | 21% | 0 | 2 | 0 | 1.6 | 72 |
| c hint marks 64/crc32 | 11/53 | 21% | 0 | 42 | 0 | 50.4 | 524 |
| d ratchet 64/crc32 +2bit | 20/53 | 38% | 0 | 33 | 0 | 57.6 | 531 |
| d ratchet 512/crc32 +2bit | 31/53 | 58% | 0 | 22 | 0 | 58.6 | 469 |
| d chain-hybrid 64/crc32 +2bit | 17/53 | 32% | 0 | 36 | 0 | 50.4 | 369 |
| d chain-pure 64/crc32 +2bit | 16/53 | 30% | 0 | 37 | 0 | 48.8 | 453 |

**Seal 8-of-16 (same payloads re-sealed) — BER 3.9e-3+rot** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 16/53 | 30% | 0 | 0 | 14 | 6481.3 | 20056 |
| a' harness model of today | 16/53 | 30% | 0 | 0 | 0 | 790.7 | 6480 |
| b hard marks 4096/crc32 | 16/53 | 30% | 0 | 0 | 0 | 731.7 | 6344 |
| b hard marks 64/crc32 | 16/53 | 30% | 0 | 0 | 0 | 679.0 | 7922 |
| c hint marks 64/crc32 | 16/53 | 30% | 0 | 0 | 0 | 750.6 | 10687 |
| d ratchet 64/crc32 +2bit | 16/53 | 30% | 0 | 2 | 0 | 738.5 | 6920 |
| d ratchet 512/crc32 +2bit | 16/53 | 30% | 0 | 1 | 0 | 725.3 | 8004 |
| d chain-hybrid 64/crc32 +2bit | 16/53 | 30% | 0 | 3 | 0 | 696.1 | 7032 |
| d chain-pure 64/crc32 +2bit | 16/53 | 30% | 0 | 3 | 0 | 657.1 | 5617 |

**Seal 8-of-16 (same payloads re-sealed) — L4+BER 1.3e-3** (36 stars)

| decoder | ok/trials | % | false acc | gate rej | timeout/budget | mean ms | max ms |
|---|---|---|---|---|---|---|---|
| a REAL sigil mend --soft (library) | 1/53 | 2% | 0 | 0 | 14 | 6567.6 | 20067 |
| a' harness model of today | 10/53 | 19% | 0 | 0 | 0 | 158.3 | 1596 |
| b hard marks 4096/crc32 | 1/53 | 2% | 0 | 0 | 0 | 0.1 | 1 |
| b hard marks 64/crc32 | 2/53 | 4% | 0 | 0 | 0 | 0.1 | 1 |
| c hint marks 64/crc32 | 10/53 | 19% | 0 | 0 | 0 | 2.5 | 13 |
| d ratchet 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 317.0 | 3228 |
| d ratchet 512/crc32 +2bit | 39/53 | 74% | 0 | 14 | 0 | 306.0 | 2794 |
| d chain-hybrid 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 275.2 | 2214 |
| d chain-pure 64/crc32 +2bit | 53/53 | 100% | 0 | 0 | 0 | 276.8 | 2313 |

rows=13527 false_accepts_total=0
