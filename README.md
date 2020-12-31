# multi-party-bls

This is a Rust implementation of {t,n}-threshold BLS. 
* The protocol is an implementation of [threshold GLOW signatures](https://eprint.iacr.org/2020/096.pdf) 
* The verification of the signatures follow the [ietf standard draft](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04), therefore, it should be possible to use this library ONLY in applications that follow the standard as well. e.g. [Algorand](https://github.com/algorand/bls_sigs_ref)
* Our DKG deviates from GLOW by assuming dishonest majority: in the case the DKG fails, the parties wll detect the faulty parties and will re-run the DKG from start without them.


## Warning
Do not use this code in production before consulting with us. Feel free to [reach out](mailto:github@kzencorp.com) or join ZenGo X [Telegram](https://t.me/zengo_x).
