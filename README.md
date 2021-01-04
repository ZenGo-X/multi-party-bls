# multi-party-bls

This is a Rust implementation of {t,n}-threshold BLS.
* The protocol is an implementation of [threshold GLOW signatures](https://eprint.iacr.org/2020/096.pdf) 
* We use [BLS12-381](https://hackmd.io/@benjaminion/bls12-381) pairing-friendly elliptic curve
* The verification of the signatures follow the [ietf standard draft](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04), therefore, it should be possible to use this library ONLY in applications that follow the standard as well. e.g. [Algorand](https://github.com/algorand/bls_sigs_ref)
* Our DKG deviates from GLOW by assuming dishonest majority: in the case the DKG fails, the parties wll detect the faulty parties and will re-run the DKG from start without them.


## Warning
Do not use this code in production before consulting with us. Feel free to [reach out](mailto:github@kzencorp.com) or join ZenGo X [Telegram](https://t.me/zengo_x).

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