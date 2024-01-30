use binsig::Pattern;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::Rng;

fn generate_bytes<'a, const LEN: usize>() -> [u8; LEN] {
    let mut rng = rand::thread_rng();
    let mut b = [0u8; LEN];
    rng.fill(&mut b);
    b
}

fn criterion_matching_benchmark(c: &mut Criterion) {
    let simple_mask_pat = Pattern::from_ida("11 ?? 22 ?? 33").unwrap();
    const VALID_SMPL_MASK_PAT: [u8; 5] = [0x11, 0xCC, 0x22, 0xCC, 0x33];
    let mut group = c.benchmark_group("is_matching");
    for bytes in [generate_bytes::<5>(), VALID_SMPL_MASK_PAT].iter() {
        group.throughput(Throughput::Bytes(bytes.len() as _));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", bytes)),
            bytes,
            |b, chk_bytes| {
                b.iter(|| simple_mask_pat.is_matching(chk_bytes));
            },
        );
    }
    group.finish();
}

fn criterion_scanning_benchmark(c: &mut Criterion) {
    let saturating_mask_pat =
        Pattern::from_ida("11 11 11 ?? ?? 22 22 22 22 22 22 ?? 33 33 33 33").unwrap();
    const KB: usize = 1024;
    let test_page = generate_bytes::<KB>();
    c.bench_function("scan 1kb", |b| {
        b.iter(|| saturating_mask_pat.scan(&test_page).collect::<Vec<_>>())
    });
}

criterion_group!(
    benches,
    criterion_matching_benchmark,
    criterion_scanning_benchmark
);
criterion_main!(benches);
