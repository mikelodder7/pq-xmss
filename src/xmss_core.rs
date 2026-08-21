use zeroize::Zeroize;

use crate::error::{Error, XmssResult};
use crate::hash::{hash_message, prf, thash_h};
use crate::hash_address::*;
use crate::params::XmssParams;
use crate::utils::{bytes_to_ull, ull_to_bytes};
use crate::wots::wots_sign;
use crate::xmss_commons::gen_leaf_wots;

/// Derived, in-memory traversal data for the next unused signing index.
///
/// This state is an acceleration cache only. The compact secret-key bytes
/// remain authoritative and are the only state serialized by the public API.
#[derive(Clone, Debug, Default)]
pub(crate) struct TraversalState {
    next_idx: Option<u64>,
    layers: Vec<Option<LayerState>>,
}

#[derive(Clone, Debug)]
struct LayerState {
    tree_idx: u64,
    leaf_idx: u32,
    root: Vec<u8>,
    auth_path: Vec<u8>,
    cached_wots: Option<CachedWotsSignature>,
}

#[derive(Clone, Debug)]
struct CachedWotsSignature {
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl TraversalState {
    pub(crate) fn from_compact_key(params: &XmssParams, sk: &[u8]) -> XmssResult<Self> {
        let n = params.n as usize;
        let idx_bytes = params.index_bytes as usize;
        let idx = bytes_to_ull(&sk[..idx_bytes]);
        let max_idx = if params.full_height >= 64 {
            u64::MAX
        } else {
            (1u64 << params.full_height) - 1
        };
        if idx > max_idx {
            return Ok(Self::default());
        }

        let sk_seed = &sk[idx_bytes..idx_bytes + n];
        let pub_seed = &sk[idx_bytes + 3 * n..idx_bytes + 4 * n];
        let mut state = Self::default();
        state.ensure(params, idx, sk_seed, pub_seed)?;
        Ok(state)
    }

    fn from_top_tree(params: &XmssParams, root: &[u8], auth_path: &[u8]) -> Self {
        let mut layers = vec![None; params.d as usize];
        layers[params.d as usize - 1] = Some(LayerState {
            tree_idx: 0,
            leaf_idx: 0,
            root: root.to_vec(),
            auth_path: auth_path.to_vec(),
            cached_wots: None,
        });
        Self {
            next_idx: Some(0),
            layers,
        }
    }

    fn clear(&mut self) {
        self.zeroize();
        self.layers.clear();
        self.next_idx = None;
    }

    fn ensure(
        &mut self,
        params: &XmssParams,
        idx: u64,
        sk_seed: &[u8],
        pub_seed: &[u8],
    ) -> XmssResult<()> {
        let layer_count = params.d as usize;
        if self.next_idx != Some(idx) || self.layers.len() != layer_count {
            self.clear();
            self.layers.resize_with(layer_count, || None);
        }

        for layer in 0..params.d {
            let (tree_idx, leaf_idx) = layer_position(params, idx, layer);
            let cached = &self.layers[layer as usize];
            if cached
                .as_ref()
                .is_some_and(|state| state.tree_idx == tree_idx && state.leaf_idx == leaf_idx)
            {
                continue;
            }

            self.layers[layer as usize] = Some(build_layer_state(
                params, layer, tree_idx, leaf_idx, sk_seed, pub_seed,
            )?);
        }
        self.next_idx = Some(idx);
        Ok(())
    }

    fn advance(
        &mut self,
        params: &XmssParams,
        idx: u64,
        sk_seed: &[u8],
        pub_seed: &[u8],
    ) -> XmssResult<()> {
        let next_idx = idx + 1;

        for layer in 0..params.d {
            let (tree_idx, leaf_idx) = layer_position(params, next_idx, layer);
            let state = self.layers[layer as usize]
                .as_mut()
                .expect("traversal state was initialized before signing");

            if state.tree_idx == tree_idx && state.leaf_idx == leaf_idx {
                continue;
            }
            if state.tree_idx == tree_idx && state.leaf_idx + 1 == leaf_idx {
                advance_auth_path(params, state, layer, sk_seed, pub_seed)?;
            } else {
                *state = build_layer_state(params, layer, tree_idx, leaf_idx, sk_seed, pub_seed)?;
            }
        }

        self.next_idx = Some(next_idx);
        Ok(())
    }
}

impl Zeroize for TraversalState {
    fn zeroize(&mut self) {
        for state in self.layers.iter_mut().flatten() {
            state.root.zeroize();
            state.auth_path.zeroize();
            if let Some(cached_wots) = &mut state.cached_wots {
                cached_wots.message.zeroize();
                cached_wots.signature.zeroize();
            }
        }
        self.next_idx = None;
    }
}

fn layer_position(params: &XmssParams, idx: u64, layer: u32) -> (u64, u32) {
    let leaf_mask = (1u64 << params.tree_height) - 1;
    let leaf_idx = (idx >> (params.tree_height * layer)) & leaf_mask;
    #[allow(clippy::cast_possible_truncation)]
    let leaf_idx = leaf_idx as u32;
    let tree_idx = idx >> (params.tree_height * (layer + 1));
    (tree_idx, leaf_idx)
}

fn build_layer_state(
    params: &XmssParams,
    layer: u32,
    tree_idx: u64,
    leaf_idx: u32,
    sk_seed: &[u8],
    pub_seed: &[u8],
) -> XmssResult<LayerState> {
    let n = params.n as usize;
    let mut root = vec![0u8; n];
    let mut auth_path = vec![0u8; params.tree_height as usize * n];
    let mut subtree_addr = [0u32; 8];
    set_layer_addr(&mut subtree_addr, layer);
    set_tree_addr(&mut subtree_addr, tree_idx);
    treehash(
        params,
        &mut root,
        &mut auth_path,
        sk_seed,
        pub_seed,
        leaf_idx,
        &subtree_addr,
    )?;
    Ok(LayerState {
        tree_idx,
        leaf_idx,
        root,
        auth_path,
        cached_wots: None,
    })
}

fn advance_auth_path(
    params: &XmssParams,
    state: &mut LayerState,
    layer: u32,
    sk_seed: &[u8],
    pub_seed: &[u8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let next_leaf = state.leaf_idx + 1;
    let changed_levels = state.leaf_idx.trailing_ones() + 1;
    let mut subtree_addr = [0u32; 8];
    set_layer_addr(&mut subtree_addr, layer);
    set_tree_addr(&mut subtree_addr, state.tree_idx);

    for height in 0..changed_levels {
        let sibling_start = ((next_leaf >> height) ^ 1) << height;
        treehash_root(
            params,
            &mut state.auth_path[height as usize * n..(height as usize + 1) * n],
            sk_seed,
            pub_seed,
            sibling_start,
            height,
            &subtree_addr,
        )?;
    }

    state.leaf_idx = next_leaf;
    state.cached_wots = None;
    Ok(())
}

/// For a given leaf index, computes the authentication path and the resulting
/// root node using the TreeHash algorithm.
fn treehash(
    params: &XmssParams,
    root: &mut [u8],
    auth_path: &mut [u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    leaf_idx: u32,
    subtree_addr: &[u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let tree_height = params.tree_height as usize;
    let mut stack = vec![0u8; (tree_height + 1) * n];
    let mut heights = vec![0u32; tree_height + 1];
    let mut offset: usize = 0;

    let mut ots_addr = [0u32; 8];
    let mut ltree_addr = [0u32; 8];
    let mut node_addr = [0u32; 8];

    copy_subtree_addr(&mut ots_addr, subtree_addr);
    copy_subtree_addr(&mut ltree_addr, subtree_addr);
    copy_subtree_addr(&mut node_addr, subtree_addr);

    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(&mut ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(&mut node_addr, XMSS_ADDR_TYPE_HASHTREE);

    let num_leaves: u32 = 1 << params.tree_height;
    for idx in 0..num_leaves {
        set_ltree_addr(&mut ltree_addr, idx);
        set_ots_addr(&mut ots_addr, idx);
        gen_leaf_wots(
            params,
            &mut stack[offset * n..(offset + 1) * n],
            sk_seed,
            pub_seed,
            &mut ltree_addr,
            &mut ots_addr,
        )?;
        offset += 1;
        heights[offset - 1] = 0;

        if (leaf_idx ^ 0x1) == idx {
            auth_path[..n].copy_from_slice(&stack[(offset - 1) * n..offset * n]);
        }

        while offset >= 2 && heights[offset - 1] == heights[offset - 2] {
            let tree_idx = idx >> (heights[offset - 1] + 1);

            set_tree_height(&mut node_addr, heights[offset - 1]);
            set_tree_index(&mut node_addr, tree_idx);
            let tmp = stack[(offset - 2) * n..offset * n].to_vec();
            thash_h(
                params,
                &mut stack[(offset - 2) * n..(offset - 1) * n],
                &tmp,
                pub_seed,
                &mut node_addr,
            )?;
            offset -= 1;
            heights[offset - 1] += 1;

            if ((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx {
                let h = heights[offset - 1] as usize;
                auth_path[h * n..(h + 1) * n].copy_from_slice(&stack[(offset - 1) * n..offset * n]);
            }
        }
    }
    root[..n].copy_from_slice(&stack[..n]);
    Ok(())
}

/// Computes the root of an aligned subtree without retaining its nodes.
fn treehash_root(
    params: &XmssParams,
    root: &mut [u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    start_idx: u32,
    target_height: u32,
    subtree_addr: &[u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let mut stack = vec![0u8; (target_height as usize + 1) * n];
    let mut heights = vec![0u32; target_height as usize + 1];
    let mut offset = 0usize;

    let mut ots_addr = [0u32; 8];
    let mut ltree_addr = [0u32; 8];
    let mut node_addr = [0u32; 8];
    copy_subtree_addr(&mut ots_addr, subtree_addr);
    copy_subtree_addr(&mut ltree_addr, subtree_addr);
    copy_subtree_addr(&mut node_addr, subtree_addr);
    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(&mut ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(&mut node_addr, XMSS_ADDR_TYPE_HASHTREE);

    let end_idx = start_idx + (1u32 << target_height);
    for idx in start_idx..end_idx {
        set_ltree_addr(&mut ltree_addr, idx);
        set_ots_addr(&mut ots_addr, idx);
        gen_leaf_wots(
            params,
            &mut stack[offset * n..(offset + 1) * n],
            sk_seed,
            pub_seed,
            &mut ltree_addr,
            &mut ots_addr,
        )?;
        offset += 1;
        heights[offset - 1] = 0;

        while offset >= 2 && heights[offset - 1] == heights[offset - 2] {
            let node_height = heights[offset - 1];
            set_tree_height(&mut node_addr, node_height);
            set_tree_index(&mut node_addr, idx >> (node_height + 1));
            let tmp = stack[(offset - 2) * n..offset * n].to_vec();
            thash_h(
                params,
                &mut stack[(offset - 2) * n..(offset - 1) * n],
                &tmp,
                pub_seed,
                &mut node_addr,
            )?;
            offset -= 1;
            heights[offset - 1] += 1;
        }
    }

    root[..n].copy_from_slice(&stack[..n]);
    Ok(())
}

/// Returns the secret key size for the given parameter set.
pub fn xmss_xmssmt_core_sk_bytes(params: &XmssParams) -> u64 {
    params.index_bytes as u64 + 4 * params.n as u64
}

/// Derives an XMSSMT key pair from a given seed.
/// The seed must be `3 * n` bytes long.
/// Secret key format: `[index || SK_SEED || SK_PRF || root || PUB_SEED]`, where
/// the index occupies `params.index_bytes` bytes.
/// Public key format: `[root || PUB_SEED]`, omitting the algorithm OID.
pub fn xmssmt_core_seed_keypair(
    params: &XmssParams,
    pk: &mut [u8],
    sk: &mut [u8],
    seed: &[u8],
) -> XmssResult<TraversalState> {
    let n = params.n as usize;
    let idx_bytes = params.index_bytes as usize;
    let tree_height = params.tree_height as usize;
    let mut auth_path = vec![0u8; tree_height * n];
    let mut top_tree_addr = [0u32; 8];
    set_layer_addr(&mut top_tree_addr, params.d - 1);

    for b in sk[..idx_bytes].iter_mut() {
        *b = 0;
    }

    sk[idx_bytes..idx_bytes + 2 * n].copy_from_slice(&seed[..2 * n]);

    sk[idx_bytes + 3 * n..idx_bytes + 4 * n].copy_from_slice(&seed[2 * n..3 * n]);
    pk[n..2 * n].copy_from_slice(&sk[idx_bytes + 3 * n..idx_bytes + 4 * n]);

    // Copy pub_seed because pk is mutably borrowed by treehash.
    let pub_seed_copy = pk[n..2 * n].to_vec();
    treehash(
        params,
        pk,
        &mut auth_path,
        &sk[idx_bytes..],
        &pub_seed_copy,
        0,
        &top_tree_addr,
    )?;
    sk[idx_bytes + 2 * n..idx_bytes + 3 * n].copy_from_slice(&pk[..n]);

    let mut traversal = TraversalState::from_top_tree(params, &pk[..n], &auth_path);
    traversal.ensure(
        params,
        0,
        &sk[idx_bytes..idx_bytes + n],
        &sk[idx_bytes + 3 * n..idx_bytes + 4 * n],
    )?;
    Ok(traversal)
}

/// Generates an XMSSMT key pair for a given parameter set.
/// Secret key format: `[index || SK_SEED || SK_PRF || root || PUB_SEED]`, where
/// the index occupies `params.index_bytes` bytes.
/// Public key format: `[root || PUB_SEED]`, omitting the algorithm OID.
pub fn xmssmt_core_keypair<R: rand::CryptoRng>(
    params: &XmssParams,
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
) -> XmssResult<TraversalState> {
    let n = params.n as usize;
    let mut seed = vec![0u8; 3 * n];

    rng.fill_bytes(&mut seed[..]);
    let result = xmssmt_core_seed_keypair(params, pk, sk, &seed);
    seed.zeroize();
    result
}

/// Signs a message, returns the signature followed by the message, and updates
/// the secret key in place.
pub fn xmssmt_core_sign(
    params: &XmssParams,
    sk: &mut [u8],
    traversal: &mut TraversalState,
    m: &[u8],
) -> XmssResult<Vec<u8>> {
    let n = params.n as usize;
    let idx_bytes = params.index_bytes as usize;
    let mlen = m.len();
    let sig_bytes = params.sig_bytes as usize;

    let sk_seed_start = idx_bytes;
    let sk_prf_start = idx_bytes + n;
    let pub_root_start = idx_bytes + 2 * n;
    let pub_seed_start = idx_bytes + 3 * n;

    let idx = bytes_to_ull(&sk[..idx_bytes]);

    // Check whether the key is exhausted before doing anything.
    let max_idx = if params.full_height >= 64 {
        u64::MAX
    } else {
        (1u64 << params.full_height) - 1
    };
    if idx > max_idx {
        traversal.clear();
        return Err(Error::KeyExhausted);
    }

    // Copy secret values out before mutating sk.
    let mut sk_seed = sk[sk_seed_start..sk_seed_start + n].to_vec();
    let mut sk_prf = sk[sk_prf_start..sk_prf_start + n].to_vec();
    let pub_root = sk[pub_root_start..pub_root_start + n].to_vec();
    let pub_seed = sk[pub_seed_start..pub_seed_start + n].to_vec();

    traversal.ensure(params, idx, &sk_seed, &pub_seed)?;

    let mut sm = vec![0u8; sig_bytes + mlen];

    let mut ots_addr = [0u32; 8];
    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);

    sm[sig_bytes..].copy_from_slice(m);

    // Write index into signature.
    sm[..idx_bytes].copy_from_slice(&sk[..idx_bytes]);

    // Advance the index in sk.
    if idx == max_idx {
        // This is the last valid index; mark the key as exhausted for the next call.
        for b in sk[..idx_bytes].iter_mut() {
            *b = 0xFF;
        }
    } else {
        ull_to_bytes(&mut sk[..idx_bytes], idx + 1);
    }

    // Compute R (randomness for message hashing).
    let mut idx_bytes_32 = [0u8; 32];
    ull_to_bytes(&mut idx_bytes_32, idx);
    prf(
        params,
        &mut sm[idx_bytes..idx_bytes + n],
        &idx_bytes_32,
        &sk_prf,
    )?;

    let mut root = vec![0u8; n];
    let prefix_len = params.padding_len as usize + 3 * n;
    let prefix_start = sig_bytes - prefix_len;
    // Copy R to avoid a borrow conflict: sm is read for R and mutated for the prefix.
    let r_val = sm[idx_bytes..idx_bytes + n].to_vec();
    hash_message(
        params,
        &mut root,
        &r_val,
        &pub_root,
        idx,
        &mut sm[prefix_start..],
        mlen as u64,
    )?;

    let mut sm_offset = idx_bytes + n;

    for i in 0..params.d {
        let (tree_idx, idx_leaf) = layer_position(params, idx, i);

        set_layer_addr(&mut ots_addr, i);
        set_tree_addr(&mut ots_addr, tree_idx);
        set_ots_addr(&mut ots_addr, idx_leaf);

        let layer_state = traversal.layers[i as usize]
            .as_mut()
            .expect("traversal state was initialized before signing");
        let reusable_wots = layer_state
            .cached_wots
            .as_ref()
            .filter(|cached_wots| cached_wots.message == root);
        if i == 0 {
            wots_sign(
                params,
                &mut sm[sm_offset..],
                &root,
                &sk_seed,
                &pub_seed,
                &mut ots_addr,
            )?;
        } else if let Some(cached_wots) = reusable_wots {
            sm[sm_offset..sm_offset + params.wots_sig_bytes as usize]
                .copy_from_slice(&cached_wots.signature);
        } else {
            let mut signature = vec![0u8; params.wots_sig_bytes as usize];
            wots_sign(
                params,
                &mut signature,
                &root,
                &sk_seed,
                &pub_seed,
                &mut ots_addr,
            )?;
            sm[sm_offset..sm_offset + signature.len()].copy_from_slice(&signature);
            layer_state.cached_wots = Some(CachedWotsSignature {
                message: root.clone(),
                signature,
            });
        }
        sm_offset += params.wots_sig_bytes as usize;

        sm[sm_offset..sm_offset + layer_state.auth_path.len()]
            .copy_from_slice(&layer_state.auth_path);
        root.copy_from_slice(&layer_state.root);
        sm_offset += params.tree_height as usize * n;
    }

    if idx == max_idx {
        traversal.clear();
    } else {
        traversal.advance(params, idx, &sk_seed, &pub_seed)?;
    }

    // Zeroize secret copies.
    sk_seed.zeroize();
    sk_prf.zeroize();

    // If this was the last valid index, zero the secret key material in sk.
    if idx == max_idx {
        #[allow(clippy::cast_possible_truncation)]
        let sk_bytes_len = params.sk_bytes as usize;
        for b in sk[idx_bytes..sk_bytes_len].iter_mut() {
            *b = 0;
        }
    }

    Ok(sm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{XmssMtSha2_20_2_256, XmssParameter};
    use crate::xmss_commons::xmssmt_core_sign_open;

    #[test]
    fn traversal_crosses_xmssmt_subtree_boundaries() {
        let mut params = XmssMtSha2_20_2_256::xmss_params();
        params.full_height = 4;
        params.tree_height = 2;
        params.d = 2;
        params.index_bytes = 1;
        params.sig_bytes = params.index_bytes
            + params.n
            + params.d * params.wots_sig_bytes
            + params.full_height * params.n;
        params.pk_bytes = 2 * params.n;
        params.sk_bytes = xmss_xmssmt_core_sk_bytes(&params);

        let mut pk = vec![0u8; params.pk_bytes as usize];
        let mut sk = vec![0u8; params.sk_bytes as usize];
        let seed: Vec<u8> = (0..params.get_seed_length())
            .map(|value| value as u8)
            .collect();
        let mut traversal = xmssmt_core_seed_keypair(&params, &mut pk, &mut sk, &seed).unwrap();

        for index in 0u8..16 {
            let message = [index];
            let signature = xmssmt_core_sign(&params, &mut sk, &mut traversal, &message).unwrap();
            assert_eq!(signature[0], index);

            let mut recovered = Vec::new();
            xmssmt_core_sign_open(&params, &mut recovered, &signature, &pk).unwrap();
            assert_eq!(recovered, message);
        }

        assert_eq!(sk[0], 0xff);
        assert!(sk[1..].iter().all(|byte| *byte == 0));
        assert!(traversal.layers.is_empty());
        assert!(matches!(
            xmssmt_core_sign(&params, &mut sk, &mut traversal, b"exhausted"),
            Err(Error::KeyExhausted)
        ));
    }
}
