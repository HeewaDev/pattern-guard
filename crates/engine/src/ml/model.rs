//! Explainable scoring model: standardised logistic regression over [`FEATURE_NAMES`].
//!
//! `p(attack) = σ(b + Σ wᵢ·(xᵢ − μᵢ)/sᵢ)`. Each term `wᵢ·(xᵢ − μᵢ)/sᵢ` is that signal's
//! contribution in log-odds, which is what [`Assessment::reasons`](crate::Assessment)
//! reports. Models are plain TOML so they can be inspected, diffed and versioned.
//!
//! Train your own on labelled traffic with `pattern-guard train` (see docs/ML.md).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::ml::features::{FEATURE_NAMES, Features, N_FEATURES};

const BUILTIN: &str = include_str!("default_model.toml");

/// On-disk form; feature order is by name so models survive feature additions.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModelFile {
    format: u32,
    description: String,
    bias: f64,
    features: Vec<FeatureWeight>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeatureWeight {
    name: String,
    weight: f64,
    mean: f64,
    scale: f64,
}

#[derive(Debug, Clone)]
pub struct Model {
    pub description: String,
    bias: f64,
    weights: Features,
    mean: Features,
    scale: Features,
    /// Features of this engine that the model file doesn't name (they weigh 0).
    missing: Vec<&'static str>,
    /// Names in the model file that this engine doesn't compute (ignored).
    unknown: Vec<String>,
}

impl Model {
    /// The model shipped with the crate (trained on synthetic traffic; see docs/ML.md).
    pub fn builtin() -> Self {
        Self::from_toml_str(BUILTIN).expect("built-in model is valid")
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let s =
            std::fs::read_to_string(path).map_err(|e| Error::ModelLoad(path.to_path_buf(), e))?;
        Self::from_toml_str(&s)
    }

    pub fn from_toml_str(s: &str) -> Result<Self, Error> {
        let file: ModelFile = toml::from_str(s).map_err(|e| Error::ModelParse(e.to_string()))?;
        if file.format != 1 {
            return Err(Error::ModelParse(format!(
                "unsupported model format {} (expected 1)",
                file.format
            )));
        }
        let mut m = Model {
            description: file.description,
            bias: file.bias,
            weights: [0.0; N_FEATURES],
            mean: [0.0; N_FEATURES],
            scale: [1.0; N_FEATURES],
            missing: Vec::new(),
            unknown: Vec::new(),
        };
        let mut matched = 0;
        let mut named = [false; N_FEATURES];
        for fw in file.features {
            // Unknown names (from newer versions) are ignored; missing ones get weight 0.
            let Some(i) = FEATURE_NAMES.iter().position(|n| *n == fw.name) else {
                m.unknown.push(fw.name);
                continue;
            };
            if !(fw.weight.is_finite() && fw.mean.is_finite() && fw.scale > 0.0) {
                return Err(Error::ModelParse(format!(
                    "bad values for feature {}",
                    fw.name
                )));
            }
            named[i] = true;
            m.weights[i] = fw.weight;
            m.mean[i] = fw.mean;
            m.scale[i] = fw.scale;
            matched += 1;
        }
        if matched == 0 {
            return Err(Error::ModelParse("model has no known features".into()));
        }
        m.missing = (0..N_FEATURES)
            .filter(|&i| !named[i])
            .map(|i| FEATURE_NAMES[i])
            .collect();
        Ok(m)
    }

    /// Whether the model names exactly the features this engine computes
    /// ([`FEATURE_NAMES`]). Loading accepts a partial match (missing features weigh 0,
    /// unknown ones are ignored), so an older model still starts after an upgrade;
    /// [`Guard::reload`](crate::Guard::reload) requires this check to pass.
    pub fn check_layout(&self) -> Result<(), Error> {
        let mut problems = Vec::new();
        if !self.missing.is_empty() {
            problems.push(format!("lacks {}", self.missing.join(", ")));
        }
        if !self.unknown.is_empty() {
            problems.push(format!("has unknown {}", self.unknown.join(", ")));
        }
        if problems.is_empty() {
            return Ok(());
        }
        Err(Error::ModelParse(format!(
            "{:?} was trained for another feature layout: it {} (retrain it with this version)",
            self.description,
            problems.join(" and ")
        )))
    }

    pub fn to_toml_string(&self) -> String {
        let file = ModelFile {
            format: 1,
            description: self.description.clone(),
            bias: self.bias,
            features: (0..N_FEATURES)
                .map(|i| FeatureWeight {
                    name: FEATURE_NAMES[i].to_string(),
                    weight: round6(self.weights[i]),
                    mean: round6(self.mean[i]),
                    scale: round6(self.scale[i]),
                })
                .collect(),
        };
        toml::to_string(&file).expect("model serialises")
    }

    /// Returns (probability of abuse, per-feature log-odds contributions).
    pub fn predict(&self, x: &Features) -> (f64, Features) {
        let mut contrib = [0.0; N_FEATURES];
        let mut z = self.bias;
        for i in 0..N_FEATURES {
            contrib[i] = self.weights[i] * (x[i] - self.mean[i]) / self.scale[i];
            z += contrib[i];
        }
        (sigmoid(z), contrib)
    }

    /// Weight of feature `i` (in standardised units).
    pub fn weight(&self, i: usize) -> f64 {
        self.weights[i]
    }

    pub fn weights(&self) -> impl Iterator<Item = (&'static str, f64)> + '_ {
        FEATURE_NAMES
            .iter()
            .copied()
            .zip(self.weights.iter().copied())
    }
}

fn round6(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

#[derive(Debug, Clone)]
pub struct TrainOptions {
    pub epochs: usize,
    pub learning_rate: f64,
    pub l2: f64,
}

impl Default for TrainOptions {
    fn default() -> Self {
        Self {
            epochs: 600,
            learning_rate: 0.05,
            l2: 1e-3,
        }
    }
}

/// Weighted logistic regression, full-batch Adam on standardised features.
///
/// `weights` lets callers balance classes / scenarios; pass all-ones for plain training.
pub fn train(
    x: &[Features],
    y: &[bool],
    weights: &[f64],
    opts: &TrainOptions,
    description: impl Into<String>,
) -> Model {
    assert_eq!(x.len(), y.len());
    assert_eq!(x.len(), weights.len());
    let total_w: f64 = weights.iter().sum::<f64>().max(1e-12);

    let mut mean = [0.0; N_FEATURES];
    let mut scale = [1.0; N_FEATURES];
    for (xi, wi) in x.iter().zip(weights) {
        for j in 0..N_FEATURES {
            mean[j] += wi * xi[j];
        }
    }
    mean.iter_mut().for_each(|m| *m /= total_w);
    let mut var = [0.0; N_FEATURES];
    for (xi, wi) in x.iter().zip(weights) {
        for j in 0..N_FEATURES {
            var[j] += wi * (xi[j] - mean[j]).powi(2);
        }
    }
    for j in 0..N_FEATURES {
        let s = (var[j] / total_w).sqrt();
        scale[j] = if s > 1e-9 { s } else { 1.0 };
    }

    let z: Vec<Features> = x
        .iter()
        .map(|xi| {
            let mut zi = [0.0; N_FEATURES];
            for j in 0..N_FEATURES {
                zi[j] = (xi[j] - mean[j]) / scale[j];
            }
            zi
        })
        .collect();

    // params: N weights + bias
    let mut w = [0.0; N_FEATURES + 1];
    let (mut m1, mut m2) = ([0.0; N_FEATURES + 1], [0.0; N_FEATURES + 1]);
    let (b1, b2, eps) = (0.9, 0.999, 1e-8);
    for epoch in 1..=opts.epochs {
        let mut grad = [0.0; N_FEATURES + 1];
        for ((zi, &yi), &wi) in z.iter().zip(y).zip(weights) {
            let mut s = w[N_FEATURES];
            for j in 0..N_FEATURES {
                s += w[j] * zi[j];
            }
            let err = wi * (sigmoid(s) - yi as u8 as f64);
            for j in 0..N_FEATURES {
                grad[j] += err * zi[j];
            }
            grad[N_FEATURES] += err;
        }
        for j in 0..=N_FEATURES {
            let mut g = grad[j] / total_w;
            if j < N_FEATURES {
                g += opts.l2 * w[j];
            }
            m1[j] = b1 * m1[j] + (1.0 - b1) * g;
            m2[j] = b2 * m2[j] + (1.0 - b2) * g * g;
            let mh = m1[j] / (1.0 - b1.powi(epoch as i32));
            let vh = m2[j] / (1.0 - b2.powi(epoch as i32));
            w[j] -= opts.learning_rate * mh / (vh.sqrt() + eps);
        }
    }

    let mut weights_out = [0.0; N_FEATURES];
    weights_out.copy_from_slice(&w[..N_FEATURES]);
    Model {
        description: description.into(),
        bias: w[N_FEATURES],
        weights: weights_out,
        mean,
        scale,
        missing: Vec::new(),
        unknown: Vec::new(),
    }
}

/// Features an attacker can cheaply make look legitimate: client fingerprint / user
/// agent, IP network (residential proxies), timing jitter, and a page view before the
/// real request. What the attack *does* — failing logins, enumerating ids, hammering one
/// route, volume — is not in this list.
pub const MIMICABLE_FEATURES: &[&str] = &[
    "actor_regularity",
    "cold_write",
    "subnet_new_actors",
    "subnet_fail_ratio",
    "client_fail_ratio",
    "client_new_actor_share",
    "client_route_share",
    "client_sequential",
    "surge_x_client_route_share",
    "new_actor_surge_x_client_route_share",
    "new_actor_surge_x_client_new_share",
    "fail_surge_x_client_fail_ratio",
    "client_route_share_x_new_share",
];

/// Mimicry augmentation: a copy of an abusive sample whose attacker-controllable
/// features are replaced by the legitimate mean, so the model cannot rely on them alone.
pub fn mimicry_copy(x: &Features, legit_mean: &Features) -> Features {
    let mut out = *x;
    for (i, name) in FEATURE_NAMES.iter().enumerate() {
        if MIMICABLE_FEATURES.contains(name) {
            out[i] = legit_mean[i];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mimicable_names_exist() {
        for n in MIMICABLE_FEATURES {
            assert!(FEATURE_NAMES.contains(n), "{n}");
        }
        let x = [1.0; N_FEATURES];
        let m = mimicry_copy(&x, &[0.0; N_FEATURES]);
        assert_eq!(
            m.iter().filter(|v| **v == 0.0).count(),
            MIMICABLE_FEATURES.len()
        );
    }

    #[test]
    fn builtin_loads() {
        let m = Model::builtin();
        let (p, _) = m.predict(&[0.0; N_FEATURES]);
        assert!((0.0..=1.0).contains(&p));
    }

    #[test]
    fn layout_check_wants_exactly_this_engines_features() {
        assert!(Model::builtin().check_layout().is_ok());
        let full = Model::builtin().to_toml_string();
        assert!(Model::from_toml_str(&full).unwrap().check_layout().is_ok());
        // an older model (one feature missing) and a newer one (one feature unknown) load,
        // but don't pass the check
        let older = full.replacen(
            &format!("name = \"{}\"", FEATURE_NAMES[N_FEATURES - 1]),
            "name = \"from_a_newer_version\"",
            1,
        );
        let m = Model::from_toml_str(&older).unwrap();
        let e = m.check_layout().unwrap_err().to_string();
        assert!(e.contains(FEATURE_NAMES[N_FEATURES - 1]), "{e}");
        assert!(e.contains("from_a_newer_version"), "{e}");
    }

    #[test]
    fn roundtrip_toml() {
        let m = Model::builtin();
        let back = Model::from_toml_str(&m.to_toml_string()).unwrap();
        let x = [0.5; N_FEATURES];
        assert!((m.predict(&x).0 - back.predict(&x).0).abs() < 1e-6);
    }

    #[test]
    fn rejects_garbage() {
        assert!(
            Model::from_toml_str("format = 1\ndescription=\"\"\nbias = 0.0\nfeatures = []")
                .is_err()
        );
        assert!(
            Model::from_toml_str("format = 9\ndescription=\"\"\nbias = 0.0\nfeatures = []")
                .is_err()
        );
    }

    #[test]
    fn learns_a_separable_signal() {
        let mut x = Vec::new();
        let mut y = Vec::new();
        for i in 0..400 {
            let mut f = [0.0; N_FEATURES];
            let bad = i % 2 == 0;
            f[3] = if bad { 0.9 } else { 0.1 } + (i % 7) as f64 * 0.01;
            f[0] = (i % 5) as f64; // noise
            x.push(f);
            y.push(bad);
        }
        let w = vec![1.0; x.len()];
        let m = train(&x, &y, &w, &TrainOptions::default(), "test");
        let mut bad = [0.0; N_FEATURES];
        bad[3] = 0.9;
        let mut good = [0.0; N_FEATURES];
        good[3] = 0.1;
        assert!(m.predict(&bad).0 > 0.9);
        assert!(m.predict(&good).0 < 0.1);
        let (_, c) = m.predict(&bad);
        let top = (0..N_FEATURES)
            .max_by(|&a, &b| c[a].total_cmp(&c[b]))
            .unwrap();
        assert_eq!(top, 3, "explanation points at the real signal");
    }
}
