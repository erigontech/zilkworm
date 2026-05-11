// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Fetch the SP1 guest ELF and verifying key from GitHub Releases.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

const ELF_ASSET_NAME: &str = "z6m_guest_hypercube.elf";
const VK_ASSET_NAME: &str = "z6m_guest_hypercube.vk";

/// Compiled guest payload, field-for-field matching `ere_guests_downloader::CompiledGuest`.
#[derive(Clone, Debug)]
pub struct CompiledGuest {
    /// Raw RISC-V ELF bytes.
    pub elf: Vec<u8>,
    /// SP1 verifying key (bincode-encoded).
    pub program_vk: Vec<u8>,
    /// Optional profiling ELF; unused by Zilkworm.
    pub profiling_elf: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Downloader {
    client: Client,
    elf_url: String,
    vk_url: String,
}

impl Downloader {
    /// Resolve the ELF and verifying-key asset URLs for `tag` on the given GitHub `repo_api_url`
    /// (e.g. `https://api.github.com/repos/erigontech/zilkworm`). The release JSON is fetched once.
    pub async fn from_tag(repo_api_url: &str, tag: &str) -> Result<Self> {
        let client = Client::builder()
            .user_agent("erigontech/zilkworm")
            .build()
            .context("building HTTP client")?;
        let assets = release_assets(&client, repo_api_url, tag).await?;
        let elf_url = find_asset(&assets, ELF_ASSET_NAME, tag)?;
        let vk_url = find_asset(&assets, VK_ASSET_NAME, tag)?;
        Ok(Self {
            client,
            elf_url,
            vk_url,
        })
    }

    pub async fn download(&self) -> Result<CompiledGuest> {
        let (elf, program_vk) = tokio::try_join!(
            fetch(&self.client, &self.elf_url, "guest ELF"),
            fetch(&self.client, &self.vk_url, "verifying key"),
        )?;
        Ok(CompiledGuest {
            elf,
            program_vk,
            profiling_elf: None,
        })
    }
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

async fn release_assets(client: &Client, repo_api_url: &str, tag: &str) -> Result<Vec<Asset>> {
    #[derive(Deserialize)]
    struct Release {
        assets: Vec<Asset>,
    }

    let url = format!("{repo_api_url}/releases/tags/{tag}");
    let release: Release = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("querying GitHub release")?
        .error_for_status()
        .with_context(|| format!("release not found: {tag}"))?
        .json()
        .await
        .context("parsing release JSON")?;
    Ok(release.assets)
}

fn find_asset(assets: &[Asset], asset_name: &str, tag: &str) -> Result<String> {
    assets
        .iter()
        .find(|a| a.name == asset_name)
        .map(|a| a.browser_download_url.clone())
        .with_context(|| format!("asset `{asset_name}` not found in release {tag}"))
}

async fn fetch(client: &Client, url: &str, what: &str) -> Result<Vec<u8>> {
    Ok(client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching {what}"))?
        .error_for_status()
        .with_context(|| format!("{what} asset download failed"))?
        .bytes()
        .await
        .with_context(|| format!("reading {what} body"))?
        .to_vec())
}
