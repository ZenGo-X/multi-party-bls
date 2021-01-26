# multi-party-bls

Rust implementation of {t,n}-threshold BLS over [BLS12-381](https://hackmd.io/@benjaminion/bls12-381) elliptic curve.
Currently two protocols are implemented: 
- Aggregated BLS. Based on the MSP protocol ([BDN18](https://eprint.iacr.org/2018/483.pdf), section 3.1) 
- Threshold BLS assuming dishonest majority. Based on Threshold GLOW signatures ([GLOW20](https://eprint.iacr.org/2020/096.pdf) version 20200806:135847)

## Threshold BLS performance
We deployed 3 parties at dedicated AWS t3.medium instances and measured keygen & signing running time (t=1, n=3). Here are results:
* Keygen
  * Mean: 158.4ms
  * Std: 18.4ms
* Signing
  * Mean: 45.5ms
  * Std: 21.2ms

# Demo
Using demo CLI app, you can distributedly generate key and sign data.

0. (Optional)
   Set environment variable to see log messages:
   ```bash
   export RUST_LOG=demo=trace
   ```

1. Start mediator server:
   ```bash
   cargo run --example cli -- mediator-server run
   ```
   Mediator server allow parties to communicate with each other. By default, it listens at 127.0.0.1:8333

2. Run distributed keygen by launching N parties:
   ```bash
   cargo run --example cli -- keygen -t 1 -n 3 --output target/keys/key1
   cargo run --example cli -- keygen -t 1 -n 3 --output target/keys/key2
   cargo run --example cli -- keygen -t 1 -n 3 --output target/keys/key3
   ```
   This will generate key between 3 parties with a threshold=1. Every party connects to mediator server
   and uses it to send and receive messages to/from other parties within the protocol.

   Every party will output result public key, e.g.:
   ```
   Public key: 951f5b5bc45af71346f4a7aee6b50670c07522175f7ebd671740075e4247b45f5f03206ae8274d77337eae797e0f69490cca3ee5da31eb5f8746dd942034550dff5c4695ee7160f32bfa8424d40e3690bdd7cf4d58e9ab5d03d00d50fc837278
   ```

   Parties private local shares will be in `target/keys` folder

3. Let's sign some data using 2 parties:
   ```bash
   cargo run --example cli -- sign -n 2 --key target/keys/key1 --digest some-data
   cargo run --example cli -- sign -n 2 --key target/keys/key2 --digest some-data
   ```

   Every party will output the same signature, e.g.:
   ```
   Signature: acbac87f8168d866df8d1f605cf8d688c64ae491e6d6cbc60db4fc0952dc097452f252cb2f746a948bac0e2311e6c14e
   ```

4. Then lets check that signature is indeed valid.
   You can use command:
   ```bash
   cargo run --example cli -- verify --digest DATA --signature SIG --public-key PK
   ```

   E.g.:
   ```bash
   cargo run --example cli -- verify --digest some-data \
     --signature acbac87f8168d866df8d1f605cf8d688c64ae491e6d6cbc60db4fc0952dc097452f252cb2f746a948bac0e2311e6c14e \
     --public-key 951f5b5bc45af71346f4a7aee6b50670c07522175f7ebd671740075e4247b45f5f03206ae8274d77337eae797e0f69490cca3ee5da31eb5f8746dd942034550dff5c4695ee7160f32bfa8424d40e3690bdd7cf4d58e9ab5d03d00d50fc837278
   ```

   Output:
   ```
   Signature is valid
   ```

**_Note_** that if you need to run several protocols (keygen/sign) concurrently, you need to provide a unique 
identifier to each group of parties by specifying `--room-id` flag. To learn more, see 
`cargo run --example cli -- keygen --help`

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
   It'll contain results of benchmarks along with nice-rendered charts.
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

# Warning
Do not use this code in production before consulting with us. Feel free to [reach out](mailto:github@zengo.com) or join ZenGo X [Telegram](https://t.me/joinchat/ET1mddGXRoyCxZ-7).
