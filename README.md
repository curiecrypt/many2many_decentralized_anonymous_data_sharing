# A Many-to-Many Decentralized Anonymous Data Sharing

This is the Sage-Python implementation of the protocol proposed in the paper **A Many-to-Many Decentralized Anonymous Data Sharing Scheme** proposed by *E. Gunsay, B.E. Karakas, G. Orhon Kilic, and Oguz Yayla*.

* Source files are located in `src/`.
* `ds_bench_single.sage` gathers the benchmarks for single operations: Signature generation, traceability check, collecting related signature files to verify a signature, and signature verification. 
* `ds_bench.sage` gets the benchmarks for block generation and signature verification.
* `ds_profiling_single.sage` collects the profiling statistics for single operations.
* `ds_profiling_full.sage` collects the profiling statistics for block generation and signature verification.
* `ds_test.sage` runs full protocol.
* Tests are running for 256 signers.
* Run the profiling and bench scripts with
```shell
sage [your_file_name].sage [8/16/32/64/128]
```
  where `argv[1]` is the ring size.
* Note that the scripts work with the ring size of the form $2^n$.
* Bench and profiling outputs are saved in `results/`.
* See paper for protocol details.

## Disclaimer
This implementation is a PoW and is not audited. Use at your own risk!