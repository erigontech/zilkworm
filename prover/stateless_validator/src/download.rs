// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Fetch the SP1 guest ELF and program VK from GitHub Releases.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

const ELF_ASSET_NAME: &str = "z6m_guest_hypercube.elf";
const VK_ASSET_NAME: &str = "z6m_guest_hypercube.vk";

#[derive(Clone, Debug)]
pub struct CompiledGuest {
    pub elf: Vec<u8>,
    pub program_vk: Vec<u8>,
    pub profiling_elf: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Downloader {
    client: Client,
    elf_url: String,
    vk_url: String,
}

impl Downloader {
    pub async fn from_tag(repo_api_url: &str, tag: &str) -> Result<Self> {
        let client = Client::builder()
            .user_agent("erigontech/zilkworm")
            .build()
            .context("building HTTP client")?;
        let assets = release_asset_urls(&client, repo_api_url, tag).await?;
        let elf_url = assets
            .get(ELF_ASSET_NAME)
            .with_context(|| format!("asset `{ELF_ASSET_NAME}` not found in release {tag}"))?
            .clone();
        let vk_url = assets
            .get(VK_ASSET_NAME)
            .with_context(|| format!("asset `{VK_ASSET_NAME}` not found in release {tag}"))?
            .clone();
        Ok(Self { client, elf_url, vk_url })
    }

    pub async fn download(&self) -> Result<CompiledGuest> {
        let (elf, program_vk) = tokio::try_join!(
            fetch_bytes(&self.client, &self.elf_url, ELF_ASSET_NAME),
            fetch_bytes(&self.client, &self.vk_url, VK_ASSET_NAME),
        )?;
        Ok(CompiledGuest { elf, program_vk, profiling_elf: None })
    }
}

async fn fetch_bytes(client: &Client, url: &str, label: &str) -> Result<Vec<u8>> {
    Ok(client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching {label}"))?
        .error_for_status()
        .with_context(|| format!("{label} download failed"))?
        .bytes()
        .await
        .with_context(|| format!("reading {label} body"))?
        .to_vec())
}

async fn release_asset_urls(
    client: &Client,
    repo_api_url: &str,
    tag: &str,
) -> Result<HashMap<String, String>> {
    #[derive(Deserialize)]
    struct Release {
        assets: Vec<Asset>,
    }
    #[derive(Deserialize)]
    struct Asset {
        name: String,
        browser_download_url: String,
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

    Ok(release
        .assets
        .into_iter()
        .map(|a| (a.name, a.browser_download_url))
        .collect())
}
