use hashbrown::HashMap;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use rug::{Complete, Integer};
use std::{io, process::exit};

fn main() {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let values: Vec<&str> = input.trim().split_whitespace().collect();
    if values.len() != 3 {
        eprintln!(
            "Error: Expected 3 values (n, e, c) but got {}",
            values.len()
        );
        exit(1);
    }

    let n = Integer::parse(values[0]).unwrap().complete();
    let e = Integer::parse(values[1]).unwrap().complete();
    let c = Integer::parse(values[2]).unwrap().complete();

    let s: u32 = 24;
    let total_items_part1 = 1u64 << s;

    let mp = MultiProgress::new();

    let pb1 = mp.add(ProgressBar::new(total_items_part1));
    pb1.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [Part1] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );

    let vals: Vec<(String, u64)> = (1..total_items_part1)
        .into_par_iter()
        .map(|i| {
            pb1.inc(1);
            let i_big = Integer::from(i);
            let result = i_big.pow_mod(&e, &n).unwrap();
            (result.to_string(), i)
        })
        .collect();
    let mut dictionary: HashMap<String, u64> = HashMap::with_capacity(vals.len());
    for (v, i) in vals {
        dictionary.insert(v, i);
    }

    let total_items_part2: u64 = 1 << (48 - s);
    let pb2 = mp.add(ProgressBar::new(total_items_part2));
    pb2.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.blue} [Part2] [{elapsed_precise}] [{bar:40.green/blue}] {pos}/{len} ({per_sec}) ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );

    let ne = (-&e).complete();
    (1..total_items_part2).into_par_iter().for_each(|i| {
        pb2.inc(1);
        let m2e = Integer::from(i).pow_mod(&ne, &n).unwrap();
        let l = (&c * &m2e).complete() % &n;
        if let Some(r) = dictionary.get(&l.to_string()) {
            let ans = Integer::from(*r) * Integer::from(i) % &n;
            println!("{}", ans);
            exit(0)
        }
    });

    println!("No solution found");
    exit(1);
}
