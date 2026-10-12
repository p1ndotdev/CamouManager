use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read},
    sync::LazyLock,
};

const NETWORK_ZST: &[u8] = include_bytes!("../data/fingerprint-network.json.zst");
const VALUES_JSON_ZST: &[u8] = include_bytes!("../data/values.json.zst");
const VALUES_DAT_ZST: &[u8] = include_bytes!("../data/values.dat.zst");
const FPGEN_PIN_JSON: &str = include_str!("../data/fpgen-model.json");

const BEAM_WIDTH: usize = 1000;
const MAX_NODES: usize = 128;

const SKIPPED_HEAVY_NODES: &[&str] = &[
    "mimeTypes",
    "gpuInfo",
    "voices",
    "defaultCS",
    "allFonts",
];

const SOFTWARE_RENDERERS: &[&str] = &[
    "llvmpipe",
    "Microsoft Basic Render Driver",
    "SwiftShader",
    "Generic Renderer",
];

const DISCRETE_GPU_BUCKETS: &[&str] = &[
    "GeForce 8800 GTX",
    "GeForce GTX 480",
    "GeForce GTX 980",
    "Radeon R9 200 Series",
];

const NETBOOK_MAX_PIXELS: i64 = 1024 * 600;
const RFP_RENDERER: &str = "Mozilla";

const NEVER_EXPOSED_EXTENSIONS: &[&str] = &[
    "WEBGL_multi_draw",
    "WEBGL_clip_cull_distance",
    "EXT_texture_norm16",
    "WEBGL_compressed_texture_etc1",
];

const HOST_DEPENDENT_EXTENSIONS: &[&str] = &["OVR_multiview2"];

const INTEL_MAC_IGP_CORES: &[i64] = &[2, 4, 6, 8, 12, 16];
const INTEL_MAC_DGPU_CORES: &[i64] = &[2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 24, 28, 32, 36, 48, 56];

const APPLE_SILICON_PANELS: &[(i64, i64)] = &[
    (1024, 665),
    (1280, 832),
    (1470, 956),
    (1710, 1112),
    (1280, 828),
    (1440, 932),
    (1710, 1107),
    (1147, 745),
    (1352, 878),
    (1512, 982),
    (1800, 1169),
    (1312, 848),
    (1496, 967),
    (1728, 1117),
    (2056, 1329),
    (2240, 1260),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct ScreenBounds {
    pub min_width: Option<i64>,
    pub max_width: Option<i64>,
    pub min_height: Option<i64>,
    pub max_height: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct TraceEntry {
    pub b85: String,
    pub value: Value,
    pub probability: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct DetRng(u64);

impl DetRng {
    pub fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_f64(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64) * (1.0 / ((1u64 << 53) as f64))
    }

    pub fn gen_range(&mut self, len: usize) -> usize {
        if len <= 1 {
            0
        } else {
            (self.next_u64() as usize) % len
        }
    }

    pub fn sample_indices(&mut self, n: usize, k: usize) -> Vec<usize> {
        let count = k.min(n);
        let mut pool: Vec<usize> = (0..n).collect();
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let idx = self.gen_range(pool.len());
            out.push(pool.swap_remove(idx));
        }
        out
    }

    pub fn choose_weighted<'a, T>(&mut self, items: &'a [T], weight_fn: impl Fn(&T) -> f64) -> Option<&'a T> {
        if items.is_empty() {
            return None;
        }
        let total: f64 = items.iter().map(&weight_fn).sum();
        if total <= 0.0 {
            return items.first();
        }
        let mut r = self.next_f64() * total;
        for item in items {
            r -= weight_fn(item);
            if r <= 0.0 {
                return Some(item);
            }
        }
        items.last()
    }
}

static B85_DEC: LazyLock<[u8; 256]> = LazyLock::new(|| {
    const ALPHABET: &[u8; 85] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let mut table = [0xFFu8; 256];
    for (i, &b) in ALPHABET.iter().enumerate() {
        table[b as usize] = i as u8;
    }
    table
});

pub fn base85_to_usize(s: &str) -> Result<usize> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        bail!("Empty base85 string");
    }
    let padding = (5 - (bytes.len() % 5)) % 5;
    let total_len = bytes.len() + padding;
    let mut out = Vec::with_capacity((total_len / 5) * 4);

    for chunk_start in (0..total_len).step_by(5) {
        let mut acc: u64 = 0;
        for j in 0..5 {
            let pos = chunk_start + j;
            let b = if pos < bytes.len() { bytes[pos] } else { b'~' };
            let digit = B85_DEC[b as usize];
            if digit == 0xFF {
                bail!("Invalid base85 character at position {pos}");
            }
            acc = acc * 85 + (digit as u64);
        }
        if acc > u32::MAX as u64 {
            bail!("Base85 overflow in chunk starting at {chunk_start}");
        }
        out.extend_from_slice(&(acc as u32).to_be_bytes());
    }

    if padding > 0 {
        out.truncate(out.len() - padding);
    }

    let mut value: usize = 0;
    for &b in &out {
        value = (value << 8) | (b as usize);
    }
    Ok(value)
}

struct BayesianNode {
    index: usize,
    name: String,
    parent_indices: Vec<usize>,
    possible_values: Vec<String>,
    probabilities: Value,
}

impl BayesianNode {
    fn cpt_for_assignment(&self, assignment: &[&str; MAX_NODES]) -> Option<&Map<String, Value>> {
        let mut current = &self.probabilities;
        for &p_idx in &self.parent_indices {
            let p_val = assignment[p_idx];
            current = current.get(p_val)?;
        }
        let map = current.as_object()?;
        if map.is_empty() {
            None
        } else {
            Some(map)
        }
    }
}

pub struct FpgenModel {
    nodes: Vec<BayesianNode>,
    nodes_by_lower: HashMap<String, usize>,
    ancestors: Vec<Vec<usize>>,
    data_buf: Vec<u8>,
    slices: Vec<Option<(u32, u32)>>,
    firefox_b85: String,
    os_b85: HashMap<&'static str, String>,
}

static MODEL: LazyLock<FpgenModel> = LazyLock::new(|| {
    FpgenModel::load().expect("bundled fpgen Bayesian model must be valid")
});

static FIREFOX_GPUS_WIN: LazyLock<Vec<TraceEntry>> = LazyLock::new(|| {
    MODEL.trace_firefox("gpu", "win", &[]).expect("Windows Firefox GPUs must trace")
});
static FIREFOX_GPUS_MAC: LazyLock<Vec<TraceEntry>> = LazyLock::new(|| {
    MODEL.trace_firefox("gpu", "mac", &[]).expect("macOS Firefox GPUs must trace")
});
static FIREFOX_GPUS_LIN: LazyLock<Vec<TraceEntry>> = LazyLock::new(|| {
    MODEL.trace_firefox("gpu", "lin", &[]).expect("Linux Firefox GPUs must trace")
});

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decompress_zst(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = zstd::Decoder::new(Cursor::new(bytes))?;
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

impl FpgenModel {
    fn load() -> Result<Self> {
        let pin: Value = serde_json::from_str(FPGEN_PIN_JSON).context("Invalid fpgen-model.json")?;
        let file_hashes = pin
            .get("file_sha256")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("Missing file_sha256 in fpgen-model.json"))?;

        for (name, bytes) in [
            ("fingerprint-network.json.zst", NETWORK_ZST),
            ("values.json.zst", VALUES_JSON_ZST),
            ("values.dat.zst", VALUES_DAT_ZST),
        ] {
            let expected = file_hashes
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("Missing pinned sha256 for {name}"))?;
            let actual = sha256_hex(bytes);
            if actual != expected {
                bail!("Pinned sha256 mismatch for {name}: expected {expected}, got {actual}");
            }
        }

        let net_raw = decompress_zst(NETWORK_ZST)?;
        let net_json: Value = serde_json::from_slice(&net_raw)?;
        let raw_nodes = net_json
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("Missing nodes array in fingerprint-network.json"))?;

        if raw_nodes.len() > MAX_NODES {
            bail!("Bayesian network node count {} exceeds MAX_NODES {}", raw_nodes.len(), MAX_NODES);
        }

        let values_raw = decompress_zst(VALUES_JSON_ZST)?;
        let values_json: Value = serde_json::from_slice(&values_raw)?;
        let values_map = values_json
            .as_object()
            .ok_or_else(|| anyhow!("values.json must be a JSON object"))?;

        let mut needed = vec![false; values_map.len()];
        let mut nodes_by_lower = HashMap::with_capacity(raw_nodes.len());
        let mut temp_nodes = Vec::with_capacity(raw_nodes.len());

        for (index, node_def) in raw_nodes.iter().enumerate() {
            let name = node_def
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("Node missing name"))?
                .to_owned();
            let parent_names = node_def
                .get("parentNames")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("Node {name} missing parentNames"))?
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_owned())
                .collect::<Vec<_>>();
            let possible_values = node_def
                .get("possibleValues")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("Node {name} missing possibleValues"))?
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_owned())
                .collect::<Vec<_>>();
            let probabilities = node_def
                .get("conditionalProbabilities")
                .cloned()
                .unwrap_or_else(|| json!({}));

            if !SKIPPED_HEAVY_NODES.contains(&name.as_str()) {
                for b85 in &possible_values {
                    let v_idx = base85_to_usize(b85)?;
                    if v_idx >= needed.len() {
                        bail!("Base85 index {v_idx} out of bounds for node {name}");
                    }
                    needed[v_idx] = true;
                }
            }

            nodes_by_lower.insert(name.to_ascii_lowercase(), index);
            temp_nodes.push((index, name, parent_names, possible_values, probabilities));
        }

        let mut nodes = Vec::with_capacity(temp_nodes.len());
        for (index, name, parent_names, possible_values, probabilities) in temp_nodes {
            let mut parent_indices = Vec::with_capacity(parent_names.len());
            for p_name in &parent_names {
                let &p_idx = nodes_by_lower
                    .get(&p_name.to_ascii_lowercase())
                    .ok_or_else(|| anyhow!("Unknown parent node {p_name} for {name}"))?;
                parent_indices.push(p_idx);
            }
            nodes.push(BayesianNode {
                index,
                name,
                parent_indices,
                possible_values,
                probabilities,
            });
        }

        let mut ancestors = Vec::with_capacity(nodes.len());
        for i in 0..nodes.len() {
            let mut set = HashSet::new();
            let mut stack = nodes[i].parent_indices.clone();
            while let Some(p_idx) = stack.pop() {
                if set.insert(p_idx) {
                    stack.extend_from_slice(&nodes[p_idx].parent_indices);
                }
            }
            let mut list: Vec<usize> = set.into_iter().collect();
            list.sort_unstable();
            ancestors.push(list);
        }

        let total_needed_bytes: usize = values_map
            .values()
            .enumerate()
            .filter_map(|(idx, v)| needed[idx].then(|| v.as_u64().unwrap_or(0) as usize))
            .sum();

        let mut data_buf = Vec::with_capacity(total_needed_bytes);
        let mut slices = vec![None; values_map.len()];
        let mut decoder = zstd::Decoder::new(Cursor::new(VALUES_DAT_ZST))?;
        let mut skip_buf = [0u8; 64 * 1024];
        let mut expected_offset: usize = 0;

        for (idx, (offset_hex, len_val)) in values_map.iter().enumerate() {
            let offset = usize::from_str_radix(offset_hex, 16)
                .with_context(|| format!("Invalid hex offset {offset_hex}"))?;
            if offset != expected_offset {
                bail!("Non-contiguous offset in values.json at index {idx}: expected {expected_offset}, got {offset}");
            }
            let len = len_val
                .as_u64()
                .ok_or_else(|| anyhow!("Invalid length in values.json at index {idx}"))?
                as usize;
            expected_offset += len;

            if needed[idx] {
                let start = data_buf.len() as u32;
                data_buf.resize(start as usize + len, 0);
                decoder.read_exact(&mut data_buf[start as usize..start as usize + len])?;
                slices[idx] = Some((start, len as u32));
            } else {
                let mut remaining = len;
                while remaining > 0 {
                    let chunk = remaining.min(skip_buf.len());
                    decoder.read_exact(&mut skip_buf[..chunk])?;
                    remaining -= chunk;
                }
            }
        }

        let mut model = Self {
            nodes,
            nodes_by_lower,
            ancestors,
            data_buf,
            slices,
            firefox_b85: String::new(),
            os_b85: HashMap::new(),
        };

        model.firefox_b85 = model
            .find_node_value_b85("browser", "\"firefox\"")
            .ok_or_else(|| anyhow!("Firefox missing from browser node"))?;
        for (short, target_json) in [
            ("win", "\"windows\""),
            ("mac", "\"macos\""),
            ("lin", "\"linux\""),
        ] {
            let b85 = model
                .find_node_value_b85("os", target_json)
                .ok_or_else(|| anyhow!("OS {target_json} missing from os node"))?;
            model.os_b85.insert(short, b85);
        }

        Ok(model)
    }

    pub fn lookup_raw(&self, b85: &str) -> Result<&str> {
        let idx = base85_to_usize(b85)?;
        let (start, len) = self
            .slices
            .get(idx)
            .and_then(|s| *s)
            .ok_or_else(|| anyhow!("Lookup index {idx} ({b85}) not loaded"))?;
        std::str::from_utf8(&self.data_buf[start as usize..(start + len) as usize])
            .context("Invalid UTF-8 in values.dat")
    }

    pub fn lookup_json(&self, b85: &str) -> Result<Value> {
        let raw = self.lookup_raw(b85)?;
        serde_json::from_str(raw).with_context(|| format!("Invalid JSON for lookup {b85}"))
    }

    fn find_node_value_b85(&self, node_name: &str, expected_lower_json: &str) -> Option<String> {
        let &node_idx = self.nodes_by_lower.get(&node_name.to_ascii_lowercase())?;
        for b85 in &self.nodes[node_idx].possible_values {
            if let Ok(raw) = self.lookup_raw(b85) {
                if raw.to_ascii_lowercase() == expected_lower_json {
                    return Some(b85.clone());
                }
            }
        }
        None
    }

    fn trace_raw<'a>(
        &'a self,
        target_idx: usize,
        evidence: &HashMap<usize, HashSet<&'a str>>,
        exclude_node: Option<usize>,
    ) -> Vec<(&'a str, f64)> {
        let mut relevant = [false; MAX_NODES];
        relevant[target_idx] = true;
        for &anc in &self.ancestors[target_idx] {
            relevant[anc] = true;
        }
        for (&ev_idx, _) in evidence {
            if Some(ev_idx) == exclude_node {
                continue;
            }
            relevant[ev_idx] = true;
            for &anc in &self.ancestors[ev_idx] {
                relevant[anc] = true;
            }
        }

        let ordered_indices: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| relevant[i])
            .collect();

        let mut beam: Vec<([&'a str; MAX_NODES], f64)> = vec![([""; MAX_NODES], 1.0)];

        for &node_idx in &ordered_indices {
            let node = &self.nodes[node_idx];
            let allowed = if Some(node_idx) == exclude_node {
                None
            } else {
                evidence.get(&node_idx)
            };

            let mut new_beam = Vec::new();

            for (assignment, prob) in &beam {
                if let Some(cpt) = node.cpt_for_assignment(assignment) {
                    for (val_str, p_val) in cpt {
                        let p = p_val.as_f64().unwrap_or(0.0);
                        if p > 0.0 && allowed.is_none_or(|set| set.contains(val_str.as_str())) {
                            let mut next_assign = *assignment;
                            next_assign[node_idx] = val_str.as_str();
                            new_beam.push((next_assign, prob * p));
                        }
                    }
                } else if !node.possible_values.is_empty() {
                    let uniform = 1.0 / (node.possible_values.len() as f64);
                    for val_str in &node.possible_values {
                        if allowed.is_none_or(|set| set.contains(val_str.as_str())) {
                            let mut next_assign = *assignment;
                            next_assign[node_idx] = val_str.as_str();
                            new_beam.push((next_assign, prob * uniform));
                        }
                    }
                }
            }

            if new_beam.is_empty() {
                return Vec::new();
            }

            if new_beam.len() > BEAM_WIDTH {
                new_beam.sort_by(|a, b| b.1.total_cmp(&a.1));
                new_beam.truncate(BEAM_WIDTH);
            }
            beam = new_beam;
        }

        let mut dist: Vec<(&'a str, f64)> = Vec::new();
        let mut pos_by_val: HashMap<&'a str, usize> = HashMap::new();
        let mut total_prob = 0.0;

        for (assignment, prob) in &beam {
            let val = assignment[target_idx];
            if !val.is_empty() {
                if let Some(&pos) = pos_by_val.get(val) {
                    dist[pos].1 += *prob;
                } else {
                    pos_by_val.insert(val, dist.len());
                    dist.push((val, *prob));
                }
                total_prob += *prob;
            }
        }

        if total_prob > 0.0 {
            for item in &mut dist {
                item.1 /= total_prob;
            }
            dist
        } else {
            Vec::new()
        }
    }

    fn validate_evidence<'a>(&'a self, evidence: &HashMap<usize, HashSet<&'a str>>) -> Result<()> {
        if evidence.len() <= 1 {
            return Ok(());
        }
        for (&node_idx, allowed_values) in evidence {
            let mut fixed: HashMap<usize, HashSet<&'a str>> = HashMap::new();
            for (&k, v) in evidence {
                if k != node_idx && v.len() == 1 {
                    fixed.insert(k, v.clone());
                }
            }
            if !fixed.is_empty() {
                let dist = self.trace_raw(node_idx, &fixed, None);
                if !dist.is_empty() {
                    let any_positive = dist
                        .iter()
                        .any(|(val, p)| *p > 0.0 && allowed_values.contains(val));
                    if !any_positive {
                        bail!(
                            "RestrictiveConstraints: node '{}' has no compatible values given fixed constraints",
                            self.nodes[node_idx].name
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn generate_consistent_sample<'a>(
        &'a self,
        initial_evidence: &HashMap<usize, HashSet<&'a str>>,
        rng: &mut impl Rng,
    ) -> Result<Vec<&'a str>> {
        let mut current_evidence = initial_evidence.clone();
        let mut sampled: Vec<&'a str> = vec![""; self.nodes.len()];

        let max_initial_constrained_idx = initial_evidence.keys().copied().max().unwrap_or(0);

        for node in &self.nodes {
            let node_idx = node.index;
            let chosen: &'a str = if let Some(allowed) = current_evidence.get(&node_idx).cloned() {
                let dist = self.trace_raw(node_idx, &current_evidence, Some(node_idx));
                let filtered: Vec<(&'a str, f64)> = dist
                    .into_iter()
                    .filter(|(k, v)| *v > 0.0 && allowed.contains(k))
                    .collect();
                let sum: f64 = filtered.iter().map(|(_, p)| *p).sum();
                if filtered.is_empty() || sum <= 0.0 {
                    let mut allowed_vec: Vec<&'a str> = allowed.into_iter().collect();
                    allowed_vec.sort_unstable();
                    let pick = rng.gen_range(0..allowed_vec.len());
                    allowed_vec[pick]
                } else {
                    sample_from_slice(&filtered, sum, rng)
                }
            } else if node_idx > max_initial_constrained_idx {
                let mut assign = [""; MAX_NODES];
                for &p_idx in &node.parent_indices {
                    assign[p_idx] = sampled[p_idx];
                }
                if let Some(cpt) = node.cpt_for_assignment(&assign) {
                    let r: f64 = rng.gen();
                    let mut cum = 0.0;
                    let mut picked: Option<&'a str> = None;
                    let mut first: Option<&'a str> = None;
                    for (k, v) in cpt {
                        if first.is_none() {
                            first = Some(k.as_str());
                        }
                        let p = v.as_f64().unwrap_or(0.0);
                        cum += p;
                        if r < cum {
                            picked = Some(k.as_str());
                            break;
                        }
                    }
                    picked.or(first).unwrap_or_else(|| node.possible_values[0].as_str())
                } else {
                    let pick = rng.gen_range(0..node.possible_values.len());
                    node.possible_values[pick].as_str()
                }
            } else {
                let dist = self.trace_raw(node_idx, &current_evidence, None);
                let sum: f64 = dist.iter().map(|(_, p)| *p).sum();
                if dist.is_empty() || sum <= 0.0 {
                    let pick = rng.gen_range(0..node.possible_values.len());
                    node.possible_values[pick].as_str()
                } else {
                    sample_from_slice(&dist, sum, rng)
                }
            };

            sampled[node_idx] = chosen;
            let mut single = HashSet::with_capacity(1);
            single.insert(chosen);
            current_evidence.insert(node_idx, single);
        }

        Ok(sampled)
    }

    pub fn trace_firefox(
        &self,
        target: &str,
        os_short: &str,
        pinned: &[(&str, &str)],
    ) -> Result<Vec<TraceEntry>> {
        let &target_idx = self
            .nodes_by_lower
            .get(&target.to_ascii_lowercase())
            .ok_or_else(|| anyhow!("Unknown trace target node: {target}"))?;

        let browser_idx = self.nodes_by_lower["browser"];
        let os_idx = self.nodes_by_lower["os"];
        let os_b85 = self
            .os_b85
            .get(os_short)
            .ok_or_else(|| anyhow!("Unsupported OS code: {os_short}"))?;

        let mut evidence: HashMap<usize, HashSet<&str>> = HashMap::new();
        evidence.insert(browser_idx, HashSet::from([self.firefox_b85.as_str()]));
        evidence.insert(os_idx, HashSet::from([os_b85.as_str()]));

        for &(node_name, b85) in pinned {
            let &idx = self
                .nodes_by_lower
                .get(&node_name.to_ascii_lowercase())
                .ok_or_else(|| anyhow!("Unknown pinned node: {node_name}"))?;
            let node_b85 = self.nodes[idx]
                .possible_values
                .iter()
                .find(|v| v.as_str() == b85)
                .ok_or_else(|| anyhow!("Invalid b85 value {b85} for node {node_name}"))?;
            evidence.insert(idx, HashSet::from([node_b85.as_str()]));
        }

        let dist = self.trace_raw(target_idx, &evidence, None);
        if dist.is_empty() {
            bail!("RestrictiveConstraints: No possible values for {target}");
        }

        let mut entries = Vec::with_capacity(dist.len());
        for (b85, prob) in dist {
            let val = self.lookup_json(b85)?;
            entries.push(TraceEntry {
                b85: b85.to_owned(),
                value: val,
                probability: prob,
            });
        }
        entries.sort_by(|a, b| b.probability.total_cmp(&a.probability));
        Ok(entries)
    }
}

fn sample_from_slice<'a>(dist: &[(&'a str, f64)], sum: f64, rng: &mut impl Rng) -> &'a str {
    let anchor = rng.gen::<f64>() * sum;
    let mut cum = 0.0;
    for &(val, prob) in dist {
        cum += prob;
        if anchor < cum {
            return val;
        }
    }
    dist.first().map(|(v, _)| *v).unwrap_or("")
}

pub fn normalize_os_short(os: &str) -> Result<&'static str> {
    match os.trim().to_ascii_lowercase().as_str() {
        "win" | "windows" => Ok("win"),
        "mac" | "macos" | "darwin" => Ok("mac"),
        "lin" | "linux" => Ok("lin"),
        other => bail!("Unknown OS for fingerprint generation: {other}"),
    }
}

fn flatten_conditions(map: &Map<String, Value>, prefix: &str, out: &mut Vec<(String, Value)>) {
    for (k, v) in map {
        let key = if prefix.is_empty() {
            k.to_ascii_lowercase()
        } else {
            format!("{}.{}", prefix, k.to_ascii_lowercase())
        };
        if let Some(sub) = v.as_object() {
            flatten_conditions(sub, &key, out);
        } else {
            out.push((key, v.clone()));
        }
    }
}

fn value_at_case_insensitive_path(mut current: &Value, path: &[String]) -> Option<Value> {
    for segment in path {
        let obj = current.as_object()?;
        let (_, next) = obj
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == *segment)?;
        current = next;
    }
    Some(current.clone())
}

fn value_equals_case_insensitive(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(sa), Value::String(sb)) => sa.eq_ignore_ascii_case(sb),
        _ => a == b,
    }
}

pub fn generate_with_constraints(conditions: &Map<String, Value>, strict: bool) -> Result<Value> {
    let model = &*MODEL;
    let mut flat = Vec::new();
    flatten_conditions(conditions, "", &mut flat);

    let mut evidence: HashMap<usize, HashSet<&str>> = HashMap::new();

    for (key, target_val) in flat {
        let mut node_idx_opt = model.nodes_by_lower.get(&key).copied();
        let mut nested_path: Vec<String> = Vec::new();

        if node_idx_opt.is_none() {
            let mut probe = key.as_str();
            while let Some((parent, leaf)) = probe.rsplit_once('.') {
                nested_path.push(leaf.to_ascii_lowercase());
                if let Some(&idx) = model.nodes_by_lower.get(parent) {
                    node_idx_opt = Some(idx);
                    break;
                }
                probe = parent;
            }
            nested_path.reverse();
        }

        let node_idx = node_idx_opt.ok_or_else(|| anyhow!("InvalidNode: {key} is not a valid node"))?;
        let node = &model.nodes[node_idx];

        let mut matched: HashSet<&str> = HashSet::new();
        let candidates: Vec<Value> = if let Some(arr) = target_val.as_array() {
            arr.clone()
        } else {
            vec![target_val]
        };

        for candidate in &candidates {
            let mut found_for_candidate = false;
            for b85 in &node.possible_values {
                let Ok(parsed) = model.lookup_json(b85) else {
                    continue;
                };
                if nested_path.is_empty() {
                    if value_equals_case_insensitive(&parsed, candidate) {
                        matched.insert(b85.as_str());
                        found_for_candidate = true;
                    }
                } else if let Some(sub_val) = value_at_case_insensitive_path(&parsed, &nested_path) {
                    if value_equals_case_insensitive(&sub_val, candidate) {
                        matched.insert(b85.as_str());
                        found_for_candidate = true;
                    }
                }
            }
            if !found_for_candidate {
                bail!("InvalidConstraints: {candidate} is not a possible value for {}", node.name);
            }
        }

        evidence.insert(node_idx, matched);
    }

    if let Err(err) = model.validate_evidence(&evidence) {
        if strict {
            return Err(err);
        }
    }

    let mut rng = rand::thread_rng();
    let sampled = model.generate_consistent_sample(&evidence, &mut rng)?;
    sampled_to_output_dict(model, &sampled)
}

fn sampled_to_output_dict(model: &FpgenModel, sampled: &[&str]) -> Result<Value> {
    let mut root = Map::new();
    let needed_output_nodes = [
        "navigator.userAgent",
        "navigator.appVersion",
        "navigator.oscpu",
        "navigator.platform",
        "navigator.hardwareConcurrency",
        "navigator.maxTouchPoints",
        "screen",
        "window",
        "headers.accept-encoding",
        "os",
        "browser",
    ];

    for node_name in needed_output_nodes {
        if let Some(&idx) = model.nodes_by_lower.get(&node_name.to_ascii_lowercase()) {
            let b85 = sampled[idx];
            if !b85.is_empty() {
                let val = model.lookup_json(b85)?;
                insert_unflattened(&mut root, &model.nodes[idx].name, val);
            }
        }
    }

    Ok(Value::Object(root))
}

fn insert_unflattened(root: &mut Map<String, Value>, dotted_key: &str, value: Value) {
    let parts: Vec<&str> = dotted_key.split('.').collect();
    let mut current = root;
    for &part in &parts[..parts.len() - 1] {
        let entry = current
            .entry(part.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        current = entry.as_object_mut().expect("object just ensured");
    }
    if let Some(&last) = parts.last() {
        current.insert(last.to_owned(), value);
    }
}

pub fn generate_fingerprint(
    os: &str,
    screen: Option<ScreenBounds>,
    window: Option<(i64, i64)>,
) -> Result<Value> {
    let os_short = normalize_os_short(os)?;
    let model = &*MODEL;
    let browser_idx = model.nodes_by_lower["browser"];
    let os_idx = model.nodes_by_lower["os"];
    let screen_idx = model.nodes_by_lower["screen"];

    let mut base_evidence: HashMap<usize, HashSet<&str>> = HashMap::new();
    base_evidence.insert(browser_idx, HashSet::from([model.firefox_b85.as_str()]));
    base_evidence.insert(os_idx, HashSet::from([model.os_b85[os_short].as_str()]));

    let mut rng = rand::thread_rng();
    let sampled = if let Some(bounds) = screen.filter(|b| {
        b.min_width.is_some() || b.max_width.is_some() || b.min_height.is_some() || b.max_height.is_some()
    }) {
        let mut allowed_screens = HashSet::new();
        for b85 in &model.nodes[screen_idx].possible_values {
            if let Ok(val) = model.lookup_json(b85) {
                let w = val.get("width").and_then(Value::as_i64);
                let h = val.get("height").and_then(Value::as_i64);
                if let (Some(w), Some(h)) = (w, h) {
                    let w_ok = bounds.min_width.is_none_or(|lo| w >= lo)
                        && bounds.max_width.is_none_or(|hi| w <= hi);
                    let h_ok = bounds.min_height.is_none_or(|lo| h >= lo)
                        && bounds.max_height.is_none_or(|hi| h <= hi);
                    if w_ok && h_ok {
                        allowed_screens.insert(b85.as_str());
                    }
                }
            }
        }
        if allowed_screens.is_empty() {
            model.generate_consistent_sample(&base_evidence, &mut rng)?
        } else {
            let mut ev = base_evidence.clone();
            ev.insert(screen_idx, allowed_screens);
            model
                .generate_consistent_sample(&ev, &mut rng)
                .or_else(|_| model.generate_consistent_sample(&base_evidence, &mut rng))?
        }
    } else {
        model.generate_consistent_sample(&base_evidence, &mut rng)?
    };

    let mut fp = sampled_to_output_dict(model, &sampled)?;
    if let Some((outer_w, outer_h)) = window {
        handle_window_size(&mut fp, outer_w, outer_h);
    }
    Ok(fp)
}

fn handle_window_size(fp: &mut Value, outer_width: i64, outer_height: i64) {
    let Some(obj) = fp.as_object_mut() else {
        return;
    };
    let screen_w = obj
        .get("screen")
        .and_then(|s| s.get("width"))
        .and_then(Value::as_i64)
        .unwrap_or(outer_width);
    let screen_h = obj
        .get("screen")
        .and_then(|s| s.get("height"))
        .and_then(Value::as_i64)
        .unwrap_or(outer_height);

    let win = obj
        .entry("window")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("window object");

    let old_screen_x = win.get("screenX").and_then(Value::as_i64).unwrap_or(0);
    let old_outer_w = win.get("outerWidth").and_then(Value::as_i64).unwrap_or(0);
    let old_outer_h = win.get("outerHeight").and_then(Value::as_i64).unwrap_or(0);

    win.insert("screenX".into(), json!(old_screen_x + (screen_w - outer_width) / 2));
    win.insert("screenY".into(), json!((screen_h - outer_height) / 2));

    if let Some(inner_w) = win.get("innerWidth").and_then(Value::as_i64).filter(|&v| v > 0) {
        win.insert("innerWidth".into(), json!((outer_width - old_outer_w + inner_w).max(0)));
    }
    if let Some(inner_h) = win.get("innerHeight").and_then(Value::as_i64).filter(|&v| v > 0) {
        win.insert("innerHeight".into(), json!((outer_height - old_outer_h + inner_h).max(0)));
    }
    win.insert("outerWidth".into(), json!(outer_width));
    win.insert("outerHeight".into(), json!(outer_height));
}

pub fn firefox_gpus(os_short: &str) -> Result<&'static [TraceEntry]> {
    match os_short {
        "win" | "windows" => Ok(FIREFOX_GPUS_WIN.as_slice()),
        "mac" | "macos" => Ok(FIREFOX_GPUS_MAC.as_slice()),
        "lin" | "linux" => Ok(FIREFOX_GPUS_LIN.as_slice()),
        other => bail!("Unsupported OS for WebGL: {other}"),
    }
}

pub fn is_software_renderer(renderer: &str) -> bool {
    !renderer.is_empty() && SOFTWARE_RENDERERS.iter().any(|name| renderer.contains(name))
}

pub fn renderer_bucket(renderer: &str) -> String {
    let mut core = renderer.strip_suffix(", or similar").unwrap_or(renderer);
    if let Some(rest) = core.strip_prefix("ANGLE (") {
        if let Some(vulkan_inner) = rest.strip_suffix(") on Vulkan") {
            core = vulkan_inner;
        } else if let Some((_, after_comma)) = rest.split_once(", ") {
            if let Some((before_d3d, _)) = after_comma.split_once(" Direct3D") {
                core = before_d3d;
            }
        }
    }
    if let Some(stripped) = core
        .strip_suffix("/PCIe/SSE2")
        .or_else(|| core.strip_suffix("/PCI/SSE2"))
    {
        core = stripped;
    }
    core.strip_prefix("NVIDIA ").unwrap_or(core).to_owned()
}

pub fn gpu_screen_is_plausible(renderer: &str, width: Option<i64>, height: Option<i64>) -> bool {
    let (Some(w), Some(h)) = (width, height) else {
        return true;
    };
    if renderer.is_empty() || w <= 0 || h <= 0 || is_software_renderer(renderer) {
        return true;
    }
    let bucket = renderer_bucket(renderer);
    if !DISCRETE_GPU_BUCKETS.contains(&bucket.as_str()) {
        return true;
    }
    w * h > NETBOOK_MAX_PIXELS
}

pub fn gpu_fits_os(renderer: &str, os_short: &str) -> bool {
    if renderer.is_empty() {
        return true;
    }
    match os_short {
        "mac" => !renderer.contains("ANGLE") && !renderer.contains("llvmpipe"),
        "win" => renderer.starts_with("ANGLE"),
        "lin" => !renderer.contains("ANGLE") && !renderer.contains("Apple M"),
        _ => true,
    }
}

pub fn intel_mac_misfit(
    renderer: &str,
    cores: Option<i64>,
    width: Option<i64>,
    height: Option<i64>,
) -> Option<String> {
    if renderer.is_empty() || renderer.contains("Apple M") {
        return None;
    }
    let allowed = if renderer.contains("Intel") {
        INTEL_MAC_IGP_CORES
    } else {
        INTEL_MAC_DGPU_CORES
    };
    if let Some(c) = cores {
        if !allowed.contains(&c) {
            return Some(format!(
                "{renderer:?} with hardwareConcurrency {c}; no Intel Mac with that GPU reports it"
            ));
        }
    }
    if let (Some(w), Some(h)) = (width, height) {
        if APPLE_SILICON_PANELS.contains(&(w, h)) {
            return Some(format!(
                "{renderer:?} behind a {w}x{h} panel, which only Apple Silicon Macs have"
            ));
        }
    }
    None
}

pub fn gpu_fits_machine(
    renderer: &str,
    os_short: &str,
    cores: Option<i64>,
    width: Option<i64>,
    height: Option<i64>,
) -> bool {
    os_short != "mac" || intel_mac_misfit(renderer, cores, width, height).is_none()
}

fn context_config(prefix: &str, webgl: &Map<String, Value>, os_short: &str) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(attrs) = webgl.get("contextAttributes") {
        out.insert(format!("{prefix}:contextAttributes"), attrs.clone());
    }
    if let Some(exts) = webgl.get("supportedExtensions").and_then(Value::as_array) {
        let filtered: Vec<Value> = exts
            .iter()
            .filter(|ext| {
                let Some(s) = ext.as_str() else {
                    return false;
                };
                if NEVER_EXPOSED_EXTENSIONS.contains(&s) {
                    return false;
                }
                if os_short != "win" && HOST_DEPENDENT_EXTENSIONS.contains(&s) {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        out.insert(format!("{prefix}:supportedExtensions"), Value::Array(filtered));
    }
    if let Some(params) = webgl.get("params").and_then(Value::as_object) {
        let mut p_map = Map::new();
        for (pname, param_obj) in params {
            if let Some(val) = param_obj.get("value") {
                p_map.insert(pname.clone(), val.clone());
            }
        }
        out.insert(format!("{prefix}:parameters"), Value::Object(p_map));
    }
    if let Some(formats) = webgl.get("shaderPrecisionFormats").and_then(Value::as_array) {
        let mut f_map = Map::new();
        for entry in formats {
            let Some(st) = entry.get("shaderType").and_then(Value::as_i64) else {
                continue;
            };
            let Some(pt) = entry.get("precisionType").and_then(Value::as_i64) else {
                continue;
            };
            if let Some(fmt) = entry.get("shaderPrecisionFormat") {
                f_map.insert(format!("{st},{pt}"), fmt.clone());
            }
        }
        out.insert(format!("{prefix}:shaderPrecisionFormats"), Value::Object(f_map));
    }
    out
}

fn build_webgl_config_for_gpu_entry(
    os_short: &str,
    gpu_entry: &TraceEntry,
    rng: &mut DetRng,
) -> Result<Map<String, Value>> {
    let model = &*MODEL;
    let webgl_candidates = model.trace_firefox("webgl", os_short, &[("gpu", &gpu_entry.b85)])?;
    let webgl_entry = rng
        .choose_weighted(&webgl_candidates, |e| e.probability)
        .ok_or_else(|| anyhow!("No recorded WebGL1 data for GPU"))?;

    let webgl2_candidates = model.trace_firefox(
        "webgl2",
        os_short,
        &[("gpu", &gpu_entry.b85), ("webgl", &webgl_entry.b85)],
    )?;
    let webgl2_entry = rng
        .choose_weighted(&webgl2_candidates, |e| e.probability)
        .ok_or_else(|| anyhow!("No recorded WebGL2 data for GPU"))?;

    let webgl_obj = webgl_entry
        .value
        .as_object()
        .ok_or_else(|| anyhow!("Invalid WebGL1 record"))?;

    let mut config = Map::new();
    if let Some(v) = webgl_obj.get("vendor") {
        config.insert("webGl:vendor".into(), v.clone());
    }
    if let Some(r) = webgl_obj.get("renderer") {
        config.insert("webGl:renderer".into(), r.clone());
    }
    config.extend(context_config("webGl", webgl_obj, os_short));

    let has_webgl2 = webgl2_entry.value.as_object().is_some_and(|m| !m.is_empty());
    config.insert("webGl2Enabled".into(), json!(has_webgl2));
    if let Some(webgl2_obj) = webgl2_entry.value.as_object().filter(|m| !m.is_empty()) {
        config.extend(context_config("webGl2", webgl2_obj, os_short));
    }

    Ok(config)
}

pub fn webgl_for_gpu(
    os_short: &str,
    vendor: &str,
    renderer: &str,
    seed: u64,
) -> Result<Map<String, Value>> {
    let os_short = normalize_os_short(os_short)?;
    let gpus = firefox_gpus(os_short)?;
    let gpu_entry = gpus
        .iter()
        .find(|entry| {
            entry.value.get("vendor").and_then(Value::as_str) == Some(vendor)
                && entry.value.get("renderer").and_then(Value::as_str) == Some(renderer)
        })
        .ok_or_else(|| {
            anyhow!("No recorded WebGL data for vendor {vendor:?} and renderer {renderer:?} on {os_short}")
        })?;
    let mut rng = DetRng::new(seed);
    build_webgl_config_for_gpu_entry(os_short, gpu_entry, &mut rng)
}

pub fn sample_webgl_for_screen(
    os_short: &str,
    width: Option<i64>,
    height: Option<i64>,
    seed: u64,
    cores: Option<i64>,
) -> Result<Map<String, Value>> {
    let os_short = normalize_os_short(os_short)?;
    let gpus = firefox_gpus(os_short)?;
    let candidates: Vec<&TraceEntry> = gpus
        .iter()
        .filter(|entry| {
            let renderer = entry
                .value
                .get("renderer")
                .and_then(Value::as_str)
                .unwrap_or("");
            !renderer.is_empty()
                && !is_software_renderer(renderer)
                && renderer != RFP_RENDERER
                && gpu_fits_os(renderer, os_short)
                && gpu_fits_machine(renderer, os_short, cores, width, height)
                && gpu_screen_is_plausible(renderer, width, height)
        })
        .collect();

    if candidates.is_empty() {
        bail!("No recorded {os_short} GPU fits a {width:?}x{height:?} screen with {cores:?} cores");
    }

    let mut rng = DetRng::new(seed);
    let chosen = *rng
        .choose_weighted(&candidates, |e| e.probability)
        .ok_or_else(|| anyhow!("Failed to choose GPU candidate"))?;
    build_webgl_config_for_gpu_entry(os_short, chosen, &mut rng)
}
