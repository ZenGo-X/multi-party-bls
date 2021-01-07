# multi-party-bls

Rust implementation of {t,n}-threshold BLS over [BLS12-381](https://hackmd.io/@benjaminion/bls12-381) elliptic curve.
Currently two protocols are implemented: 
- Aggregated BLS. Based on the MSP protocol ([BDG18](https://eprint.iacr.org/2018/483.pdf), section 3.1) 
- Threshold BLS assuming dishonest majority. Based on Threshold GLOW signatures ([GLOW](https://eprint.iacr.org/2020/096.pdf) version 20200806:135847)



## Warning
Do not use this code in production before consulting with us. Feel free to [reach out](mailto:github@zengo.com) or join ZenGo X [Telegram](https://t.me/zengo_x).

# Development

## Detecting performance regression
We use statistical-driven benchmarks backed by [criterion][criterion-crate] to detect any regressions.
Please, follow instruction to see how your changes effect on performance:
1. Checkout commit before your changes (don't forget to commit all your changes)
2. Run benchmarks:
   ```shell
   cargo bench --bench criterion --features dev
   ```
   It will take a few minutes.
   After that, you should be able to discover HTML-rendered report at `./target/criterion/report/index.html`.
   It contains results of benchmarks along with nice-rendered charts.
3. Checkout back on the commit with your changes
4. Run benchmarks again:
   ```shell
   cargo bench --bench criterion --features dev
   ```
   Criterion will report about any regression it found right in console output. HTML-rendered report
   will be updated (see `./target/criterion/report/index.html`) and will reason about performance
   differences more precisely.

[criterion-crate]: https://crates.io/crates/criterion

**_Note_** that benchmark results do not show real-world performance of multi party computation since
everything is computed sequentially, not in parallel. We do not allocate separate thread for every party
as it will make harder to reason about performance differences.
